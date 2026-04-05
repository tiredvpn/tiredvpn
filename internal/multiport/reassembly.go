package multiport

import (
	"log/slog"
	"sync"
	"time"
)

// ReceiveBuffer manages packet reassembly with out-of-order handling
type ReceiveBuffer struct {
	mu sync.RWMutex

	// State
	packets      map[uint64]*Packet // seq -> packet
	nextExpected uint64             // Next sequence number we expect
	readyChan    chan []byte        // Channel for delivering ordered data
	ackChan      chan *AckPacket    // Channel for sending ACKs

	// Configuration
	maxBufferSize int           // Max packets to buffer (default: 1000)
	cleanupAge    time.Duration // Max age for buffered packets (default: 10s)

	// Stats
	stats ReceiveStats

	// Lifecycle
	done chan struct{}
}

// ReceiveStats tracks receive buffer statistics
type ReceiveStats struct {
	PacketsReceived uint64
	PacketsDuplicate uint64
	PacketsDropped   uint64
	BytesReceived    uint64
	OutOfOrder       uint64
}

// NewReceiveBuffer creates a new receive buffer
func NewReceiveBuffer(initialSeq uint64) *ReceiveBuffer {
	rb := &ReceiveBuffer{
		packets:       make(map[uint64]*Packet),
		nextExpected:  initialSeq,
		readyChan:     make(chan []byte, 100),
		ackChan:       make(chan *AckPacket, 10),
		maxBufferSize: 1000,
		cleanupAge:    10 * time.Second,
		done:          make(chan struct{}),
	}

	// Start cleanup goroutine
	go rb.cleanupLoop()

	return rb
}

// AddPacket adds a received packet to the buffer
// Returns true if packet was accepted, false if duplicate/dropped
func (rb *ReceiveBuffer) AddPacket(pkt *Packet) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.stats.PacketsReceived++

	// Check for duplicate
	if pkt.Seq < rb.nextExpected {
		rb.stats.PacketsDuplicate++
		slog.Debug("duplicate packet", "seq", pkt.Seq, "nextExpected", rb.nextExpected)
		// Still send ACK for duplicate (helps with retransmission)
		rb.sendAck()
		return false
	}

	// Check if already buffered
	if _, exists := rb.packets[pkt.Seq]; exists {
		rb.stats.PacketsDuplicate++
		slog.Debug("duplicate buffered packet", "seq", pkt.Seq)
		rb.sendAck()
		return false
	}

	// Check buffer capacity
	if len(rb.packets) >= rb.maxBufferSize {
		rb.stats.PacketsDropped++
		slog.Warn("receive buffer full, dropping packet", "seq", pkt.Seq, "bufferSize", len(rb.packets))
		return false
	}

	// Track out-of-order
	if pkt.Seq > rb.nextExpected {
		rb.stats.OutOfOrder++
	}

	// Store packet
	rb.packets[pkt.Seq] = pkt
	rb.stats.BytesReceived += uint64(len(pkt.Payload))

	// Try to deliver continuous sequence
	rb.deliverContinuous()

	// Send ACK
	rb.sendAck()

	return true
}

// deliverContinuous delivers all continuous packets starting from nextExpected
// Must be called with lock held
func (rb *ReceiveBuffer) deliverContinuous() {
	for {
		pkt, exists := rb.packets[rb.nextExpected]
		if !exists {
			break
		}

		// Deliver payload if non-empty
		if len(pkt.Payload) > 0 {
			select {
			case rb.readyChan <- pkt.Payload:
				slog.Debug("delivered packet", "seq", pkt.Seq, "bytes", len(pkt.Payload))
			default:
				slog.Warn("ready channel full, blocking")
				// Block until channel has space
				rb.readyChan <- pkt.Payload
			}
		}

		// Remove from buffer
		delete(rb.packets, rb.nextExpected)
		rb.nextExpected++
	}
}

// sendAck generates and sends an ACK packet
// Must be called with lock held
func (rb *ReceiveBuffer) sendAck() {
	ack := &AckPacket{
		Version:   ProtocolVersion,
		Flags:     FlagACK,
		AckBase:   rb.nextExpected,
		AckBitmap: make([]byte, 32), // 256 bits
	}

	// Set bitmap for buffered packets
	for seq := range rb.packets {
		if seq >= rb.nextExpected {
			ack.SetAcked(seq)
		}
	}

	// Send non-blocking
	select {
	case rb.ackChan <- ack:
	default:
		slog.Warn("ack channel full, dropping ack")
	}
}

// ReadyChan returns the channel for reading ordered data
func (rb *ReceiveBuffer) ReadyChan() <-chan []byte {
	return rb.readyChan
}

// AckChan returns the channel for reading ACK packets to send
func (rb *ReceiveBuffer) AckChan() <-chan *AckPacket {
	return rb.ackChan
}

// cleanupLoop periodically removes old packets from buffer
func (rb *ReceiveBuffer) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rb.cleanup()
		case <-rb.done:
			return
		}
	}
}

// cleanup removes packets older than cleanupAge
func (rb *ReceiveBuffer) cleanup() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Simple cleanup: remove packets that are too far ahead
	// (more than maxBufferSize sequences ahead of nextExpected)
	threshold := rb.nextExpected + uint64(rb.maxBufferSize)

	for seq := range rb.packets {
		if seq > threshold {
			delete(rb.packets, seq)
			rb.stats.PacketsDropped++
			slog.Warn("cleaned up old packet", "seq", seq, "nextExpected", rb.nextExpected)
		}
	}
}

// Stats returns current buffer statistics
func (rb *ReceiveBuffer) Stats() ReceiveStats {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.stats
}

// Close closes the receive buffer
func (rb *ReceiveBuffer) Close() {
	close(rb.done)
	close(rb.readyChan)
	close(rb.ackChan)
}

// SendBuffer manages packet sending with retransmission
type SendBuffer struct {
	mu sync.RWMutex

	// State
	packets      map[uint64]*sendPacketState // seq -> packet state
	nextSeq      uint64                      // Next sequence to use
	retransmitCh chan uint64                 // Channel for retransmit requests

	// Configuration
	initialRTO time.Duration // Initial retransmission timeout (default: 100ms)
	maxRetries int           // Max retransmit attempts (default: 5)

	// Stats
	stats SendStats

	// Lifecycle
	done chan struct{}
}

type sendPacketState struct {
	packet      *Packet
	sendTime    time.Time
	retries     int
	rto         time.Duration // Current RTO for this packet
	timer       *time.Timer
	acknowledged bool
}

// SendStats tracks send buffer statistics
type SendStats struct {
	PacketsSent      uint64
	BytesSent        uint64
	Retransmissions  uint64
	Acknowledgments  uint64
	PacketsLost      uint64
}

// NewSendBuffer creates a new send buffer
func NewSendBuffer(initialSeq uint64) *SendBuffer {
	return &SendBuffer{
		packets:      make(map[uint64]*sendPacketState),
		nextSeq:      initialSeq,
		retransmitCh: make(chan uint64, 100),
		initialRTO:   100 * time.Millisecond,
		maxRetries:   5,
		done:         make(chan struct{}),
	}
}

// NextSeq returns the next sequence number to use
func (sb *SendBuffer) NextSeq() uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	seq := sb.nextSeq
	sb.nextSeq++
	return seq
}

// MarkSent marks a packet as sent and starts retransmission timer
func (sb *SendBuffer) MarkSent(pkt *Packet) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	state := &sendPacketState{
		packet:   pkt,
		sendTime: time.Now(),
		rto:      sb.initialRTO,
		retries:  0,
	}

	// Start retransmission timer
	state.timer = time.AfterFunc(state.rto, func() {
		sb.retransmitCh <- pkt.Seq
	})

	sb.packets[pkt.Seq] = state
	sb.stats.PacketsSent++
	sb.stats.BytesSent += uint64(len(pkt.Payload))
}

// ProcessAck processes an ACK packet
func (sb *SendBuffer) ProcessAck(ack *AckPacket) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Mark all acknowledged packets
	for seq, state := range sb.packets {
		if state.acknowledged {
			continue
		}

		if ack.IsAcked(seq) {
			state.acknowledged = true
			state.timer.Stop()
			sb.stats.Acknowledgments++
			slog.Debug("packet acknowledged", "seq", seq)
		}
	}

	// Clean up acknowledged packets
	for seq, state := range sb.packets {
		if state.acknowledged {
			delete(sb.packets, seq)
		}
	}
}

// RetransmitChan returns the channel for retransmit requests
func (sb *SendBuffer) RetransmitChan() <-chan uint64 {
	return sb.retransmitCh
}

// GetPacket returns a packet for retransmission
func (sb *SendBuffer) GetPacket(seq uint64) *Packet {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	state, exists := sb.packets[seq]
	if !exists || state.acknowledged {
		return nil
	}

	// Check max retries
	if state.retries >= sb.maxRetries {
		slog.Error("packet lost after max retries", "seq", seq, "retries", state.retries)
		state.timer.Stop()
		delete(sb.packets, seq)
		sb.stats.PacketsLost++
		return nil
	}

	// Update state for retransmission
	state.retries++
	state.rto *= 2 // Exponential backoff
	state.sendTime = time.Now()
	sb.stats.Retransmissions++

	// Reset timer
	state.timer.Reset(state.rto)

	slog.Debug("retransmitting packet", "seq", seq, "retries", state.retries, "rto", state.rto)

	return state.packet
}

// Stats returns current send buffer statistics
func (sb *SendBuffer) Stats() SendStats {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.stats
}

// Close closes the send buffer
func (sb *SendBuffer) Close() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Stop all timers
	for _, state := range sb.packets {
		if state.timer != nil {
			state.timer.Stop()
		}
	}

	close(sb.done)
	close(sb.retransmitCh)
}
