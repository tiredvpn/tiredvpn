// Package control implements the unified control channel protocol for TiredVPN.
// Control messages are multiplexed with data using a 0xCC magic byte prefix.
package control

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Message types
const (
	MsgPing      byte = 0x01 // Keepalive request (client -> server)
	MsgPong      byte = 0x02 // Keepalive response (server -> client)
	MsgStatsReq  byte = 0x03 // Request stats
	MsgStatsResp byte = 0x04 // Stats response
)

// Magic byte to identify control messages
const ControlMagic byte = 0xCC

// MinMessageSize is the minimum size of a control message header
const MinMessageSize = 5 // magic + type + seq + length(2)

// Message represents a control channel message
type Message struct {
	Type    byte
	Seq     byte
	Payload []byte
}

// Serialize converts message to wire format
func (m *Message) Serialize() []byte {
	length := len(m.Payload)
	buf := make([]byte, MinMessageSize+length)
	buf[0] = ControlMagic
	buf[1] = m.Type
	buf[2] = m.Seq
	binary.BigEndian.PutUint16(buf[3:5], uint16(length))
	if length > 0 {
		copy(buf[5:], m.Payload)
	}
	return buf
}

// ParseMessage parses a control message from wire format
// Returns nil if not a control message (doesn't start with ControlMagic)
func ParseMessage(data []byte) *Message {
	if len(data) < MinMessageSize {
		return nil
	}
	if data[0] != ControlMagic {
		return nil
	}

	length := binary.BigEndian.Uint16(data[3:5])
	if len(data) < MinMessageSize+int(length) {
		return nil
	}

	msg := &Message{
		Type: data[1],
		Seq:  data[2],
	}
	if length > 0 {
		msg.Payload = make([]byte, length)
		copy(msg.Payload, data[5:5+length])
	}
	return msg
}

// IsControlMessage checks if data starts with control magic byte
func IsControlMessage(data []byte) bool {
	return len(data) > 0 && data[0] == ControlMagic
}

// Stats holds connection statistics
type Stats struct {
	BytesSent   uint64
	BytesRecv   uint64
	LastRTT     time.Duration
	AvgRTT      time.Duration
	MissedPings int
	Uptime      time.Duration
}

// Config configures the controller
type Config struct {
	PingInterval   time.Duration // How often to send PING (default 15s)
	PingTimeout    time.Duration // Max wait for PONG (default 5s)
	MaxMissedPings int           // Disconnect after N missed pongs (default 3)
	OnUnhealthy    func(reason string)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		PingInterval:   15 * time.Second,
		PingTimeout:    5 * time.Second,
		MaxMissedPings: 3,
	}
}

// Controller manages control channel for a connection
type Controller struct {
	conn   net.Conn
	config Config

	// State
	mu          sync.Mutex
	seq         byte
	pendingPing *pendingPing
	startTime   time.Time

	// Stats (atomic)
	bytesSent   uint64
	bytesRecv   uint64
	lastRTT     int64 // nanoseconds
	rttSum      int64
	rttCount    int64
	missedPings int32

	// Lifecycle
	stopCh  chan struct{}
	stopped int32
	wg      sync.WaitGroup
}

type pendingPing struct {
	seq      byte
	sentAt   time.Time
	deadline time.Time
}

// NewController creates a new control channel controller
func NewController(conn net.Conn, config Config) *Controller {
	if config.PingInterval == 0 {
		config.PingInterval = 15 * time.Second
	}
	if config.PingTimeout == 0 {
		config.PingTimeout = 5 * time.Second
	}
	if config.MaxMissedPings == 0 {
		config.MaxMissedPings = 3
	}

	return &Controller{
		conn:      conn,
		config:    config,
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

// Start begins the keepalive loop
func (c *Controller) Start() {
	c.wg.Add(1)
	go c.keepaliveLoop()
}

// Stop gracefully stops the controller
func (c *Controller) Stop() {
	if atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		close(c.stopCh)
		c.wg.Wait()
	}
}

// HandleMessage processes an incoming control message
// Returns true if message was handled, false if not a control message
func (c *Controller) HandleMessage(data []byte) bool {
	msg := ParseMessage(data)
	if msg == nil {
		return false
	}

	switch msg.Type {
	case MsgPong:
		c.handlePong(msg)
	case MsgStatsResp:
		c.handleStatsResp(msg)
	default:
		log.Debug("Unknown control message type: 0x%02x", msg.Type)
	}

	return true
}

// SendPing sends a PING message
func (c *Controller) SendPing() error {
	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.pendingPing = &pendingPing{
		seq:      seq,
		sentAt:   time.Now(),
		deadline: time.Now().Add(c.config.PingTimeout),
	}
	c.mu.Unlock()

	msg := &Message{
		Type: MsgPing,
		Seq:  seq,
	}

	data := msg.Serialize()
	_, err := c.conn.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&c.bytesSent, uint64(len(data)))
	log.Debug("Sent PING seq=%d", seq)
	return nil
}

// Stats returns current connection statistics
func (c *Controller) Stats() Stats {
	rttCount := atomic.LoadInt64(&c.rttCount)
	var avgRTT time.Duration
	if rttCount > 0 {
		avgRTT = time.Duration(atomic.LoadInt64(&c.rttSum) / rttCount)
	}

	return Stats{
		BytesSent:   atomic.LoadUint64(&c.bytesSent),
		BytesRecv:   atomic.LoadUint64(&c.bytesRecv),
		LastRTT:     time.Duration(atomic.LoadInt64(&c.lastRTT)),
		AvgRTT:      avgRTT,
		MissedPings: int(atomic.LoadInt32(&c.missedPings)),
		Uptime:      time.Since(c.startTime),
	}
}

// AddBytesSent adds to sent bytes counter
func (c *Controller) AddBytesSent(n uint64) {
	atomic.AddUint64(&c.bytesSent, n)
}

// AddBytesRecv adds to received bytes counter
func (c *Controller) AddBytesRecv(n uint64) {
	atomic.AddUint64(&c.bytesRecv, n)
}

func (c *Controller) keepaliveLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-c.stopCh:
			return

		case <-ticker.C:
			if err := c.SendPing(); err != nil {
				log.Warn("Failed to send PING: %v", err)
				c.markUnhealthy("ping send failed")
				return
			}

		case <-checkTicker.C:
			c.checkPingTimeout()
		}
	}
}

func (c *Controller) checkPingTimeout() {
	c.mu.Lock()
	pending := c.pendingPing
	c.mu.Unlock()

	if pending == nil {
		return
	}

	if time.Now().After(pending.deadline) {
		missed := atomic.AddInt32(&c.missedPings, 1)
		log.Warn("PING timeout (seq=%d, missed=%d/%d)", pending.seq, missed, c.config.MaxMissedPings)

		c.mu.Lock()
		c.pendingPing = nil
		c.mu.Unlock()

		if int(missed) >= c.config.MaxMissedPings {
			c.markUnhealthy("too many missed pings")
		}
	}
}

func (c *Controller) handlePong(msg *Message) {
	c.mu.Lock()
	pending := c.pendingPing
	c.pendingPing = nil
	c.mu.Unlock()

	if pending == nil {
		log.Debug("Received unexpected PONG seq=%d", msg.Seq)
		return
	}

	if msg.Seq != pending.seq {
		log.Debug("PONG seq mismatch: expected=%d, got=%d", pending.seq, msg.Seq)
		return
	}

	rtt := time.Since(pending.sentAt)
	atomic.StoreInt64(&c.lastRTT, int64(rtt))
	atomic.AddInt64(&c.rttSum, int64(rtt))
	atomic.AddInt64(&c.rttCount, 1)
	atomic.StoreInt32(&c.missedPings, 0) // Reset on successful pong

	log.Debug("Received PONG seq=%d rtt=%v", msg.Seq, rtt)
}

func (c *Controller) handleStatsResp(msg *Message) {
	// Stats response from server - can be used for diagnostics
	log.Debug("Received STATS_RESP: %d bytes", len(msg.Payload))
}

func (c *Controller) markUnhealthy(reason string) {
	if c.config.OnUnhealthy != nil {
		c.config.OnUnhealthy(reason)
	}
}

// HandleServerMessage processes control messages on the server side
// This is a stateless handler that just echoes PONGs
func HandleServerMessage(conn net.Conn, data []byte) bool {
	msg := ParseMessage(data)
	if msg == nil {
		return false
	}

	switch msg.Type {
	case MsgPing:
		// Echo back PONG with same seq
		pong := &Message{
			Type: MsgPong,
			Seq:  msg.Seq,
		}
		conn.Write(pong.Serialize())
		log.Debug("Server: PING->PONG seq=%d", msg.Seq)

	case MsgStatsReq:
		// Server could send stats here if needed
		log.Debug("Server: Received STATS_REQ")

	default:
		log.Debug("Server: Unknown control message type: 0x%02x", msg.Type)
	}

	return true
}
