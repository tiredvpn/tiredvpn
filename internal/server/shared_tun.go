package server

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// SharedTUN manages a single TUN device shared by all VPN clients.
// Instead of creating one TUN per client, all clients share this interface
// and packets are multiplexed by destination IP.
type SharedTUN struct {
	tunDev   *tun.TUNDevice
	name     string     // e.g., "tiredvpn0"
	serverIP net.IP     // e.g., 10.9.0.1
	network  *net.IPNet // e.g., 10.9.0.0/24
	mtu      int

	// Client registry: IP string -> writer
	clients   map[string]*ClientWriter
	clientsMu sync.RWMutex

	// Reconnect flap detection
	reconnTracker *reconnectTracker

	// Worker pool for packet dispatch
	workers     int
	workerChans []chan *tunPacket
	bufferSize  int // Channel buffer size per worker

	// Control
	running int32
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// tunPacket holds a packet to be sent to a client
type tunPacket struct {
	data  []byte
	dstIP string
}

// ClientWriter represents a connected client that receives packets from shared TUN
type ClientWriter struct {
	conn       net.Conn
	clientIP   net.IP
	clientID   string
	lastActive int64 // Unix timestamp, updated atomically
	created    int64 // Unix timestamp of creation
	done       chan struct{}
	writeMu    sync.Mutex

	// Framing function - different protocols have different framing
	// Returns the framed packet ready to send
	framePacket func(pkt []byte) []byte
}

// reconnectTracker tracks per-client reconnect frequency to prevent flapping
type reconnectTracker struct {
	mu        sync.Mutex
	counts    map[string]*reconnectState // clientID -> state
	maxPerMin int                        // max reconnects per minute before backoff warning
}

type reconnectState struct {
	timestamps []int64 // timestamps of recent reconnects (Unix)
}

func newReconnectTracker(maxPerMin int) *reconnectTracker {
	return &reconnectTracker{
		counts:    make(map[string]*reconnectState),
		maxPerMin: maxPerMin,
	}
}

// record records a reconnect event and returns (count in last minute, is flapping)
func (rt *reconnectTracker) record(clientID string) (int, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now().Unix()
	cutoff := now - 60 // 1 minute window

	state, ok := rt.counts[clientID]
	if !ok {
		state = &reconnectState{}
		rt.counts[clientID] = state
	}

	// Prune old timestamps
	fresh := state.timestamps[:0]
	for _, ts := range state.timestamps {
		if ts > cutoff {
			fresh = append(fresh, ts)
		}
	}
	fresh = append(fresh, now)
	state.timestamps = fresh

	return len(fresh), len(fresh) > rt.maxPerMin
}

// NewSharedTUN creates and configures a shared TUN device for all clients
func NewSharedTUN(name string, serverIP net.IP, network *net.IPNet, mtu, workers int) (*SharedTUN, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	// Create TUN device with explicit name
	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}

	// Configure with subnet routing (not point-to-point)
	if err := tunDev.ConfigureSubnet(serverIP, network); err != nil {
		tunDev.Close()
		return nil, err
	}

	st := &SharedTUN{
		tunDev:        tunDev,
		name:          tunDev.Name(),
		serverIP:      serverIP,
		network:       network,
		mtu:           mtu,
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10), // warn if >10 reconnects/min
		workers:       workers,
		workerChans:   make([]chan *tunPacket, workers),
		bufferSize:    1024, // Buffer up to 1024 packets per worker
		stopCh:        make(chan struct{}),
	}

	// Initialize worker channels
	for i := 0; i < workers; i++ {
		st.workerChans[i] = make(chan *tunPacket, st.bufferSize)
	}

	// Start workers
	for i := 0; i < workers; i++ {
		st.wg.Add(1)
		go st.packetWorker(i, st.workerChans[i])
	}

	// Start packet dispatcher (reads from TUN)
	st.wg.Add(1)
	go st.packetDispatcher()

	atomic.StoreInt32(&st.running, 1)
	log.Info("SharedTUN started: %s (server=%s, network=%s, workers=%d)",
		st.name, serverIP, network, workers)

	return st, nil
}

// Name returns the TUN device name
func (st *SharedTUN) Name() string {
	return st.name
}

// TUNDevice returns the underlying TUN device for direct writes
func (st *SharedTUN) TUNDevice() *tun.TUNDevice {
	return st.tunDev
}

// RegisterClient adds a client to the shared TUN
// If client with same IP exists, old connection is gracefully drained before replacement
func (st *SharedTUN) RegisterClient(clientIP net.IP, clientID string, conn net.Conn, frameFunc func([]byte) []byte) *ClientWriter {
	ipStr := clientIP.String()
	now := time.Now().Unix()

	writer := &ClientWriter{
		conn:        conn,
		clientIP:    clientIP,
		clientID:    clientID,
		lastActive:  now,
		created:     now,
		done:        make(chan struct{}),
		framePacket: frameFunc,
	}

	// Track reconnect frequency
	count, flapping := st.reconnTracker.record(clientID)
	if flapping {
		log.Warn("SharedTUN: client %s (IP=%s) reconnecting too fast (%d times in last minute), possible flapping", clientID, ipStr, count)
	}

	st.clientsMu.Lock()
	old, hadOld := st.clients[ipStr]
	st.clients[ipStr] = writer
	st.clientsMu.Unlock()

	// Close old connection asynchronously with grace period
	if hadOld {
		oldAge := now - atomic.LoadInt64(&old.created)
		log.Info("SharedTUN: replacing connection for %s (clientID=%s, old_age=%ds, reconnect_count=%d)",
			ipStr, clientID, oldAge, count)
		go func() {
			// Grace period: let in-flight writes finish
			time.Sleep(200 * time.Millisecond)
			select {
			case <-old.done:
				// Already closed
			default:
				close(old.done)
			}
		}()
	}

	log.Info("SharedTUN: registered client %s (IP=%s)", clientID, ipStr)
	return writer
}

// UnregisterClient removes a client from the shared TUN
// If expectedWriter is not nil, only unregister if it matches the current writer
// (prevents race condition where old connection unregisters new connection)
func (st *SharedTUN) UnregisterClient(clientIP net.IP, expectedWriter *ClientWriter) {
	ipStr := clientIP.String()

	st.clientsMu.Lock()
	if writer, ok := st.clients[ipStr]; ok {
		// If expectedWriter provided, only unregister if it matches
		if expectedWriter != nil && writer != expectedWriter {
			st.clientsMu.Unlock()
			log.Debug("SharedTUN: skip unregister IP=%s (connection replaced)", ipStr)
			return
		}
		select {
		case <-writer.done:
			// Already closed
		default:
			close(writer.done)
		}
		delete(st.clients, ipStr)
		log.Info("SharedTUN: unregistered client IP=%s", ipStr)
	}
	st.clientsMu.Unlock()
}

// packetDispatcher reads packets from TUN and distributes to workers
func (st *SharedTUN) packetDispatcher() {
	defer st.wg.Done()

	buf := make([]byte, st.mtu+100)

	for {
		select {
		case <-st.stopCh:
			return
		default:
		}

		n, err := st.tunDev.Read(buf)
		if err != nil {
			if atomic.LoadInt32(&st.running) == 0 {
				return
			}
			log.Debug("SharedTUN: read error: %v", err)
			continue
		}

		if n < 20 {
			log.Debug("SharedTUN: packet too short (%d bytes)", n)
			continue // Too short for IPv4 header
		}

		if n > st.mtu {
			log.Debug("SharedTUN: oversized packet (%d > %d), dropping", n, st.mtu)
			continue
		}

		// Debug: log every packet read from TUN
		log.Debug("SharedTUN: read %d bytes from TUN, dst=%s", n, net.IP(buf[16:20]).String())

		// Check IP version
		version := buf[0] >> 4
		if version != 4 {
			log.Debug("SharedTUN: non-IPv4 packet (version=%d), dropping", version)
			continue
		}

		// Extract destination IP from IPv4 header (bytes 16-19)
		dstIP := net.IP(buf[16:20]).String()

		// Copy packet data (buf will be reused)
		pktData := make([]byte, n)
		copy(pktData, buf[:n])

		// Hash destination IP to worker index
		workerIdx := hashIP(dstIP) % st.workers

		// Send to worker (non-blocking with drop on overflow)
		pkt := &tunPacket{
			data:  pktData,
			dstIP: dstIP,
		}

		select {
		case st.workerChans[workerIdx] <- pkt:
			log.Debug("SharedTUN: dispatched to worker %d for dst=%s", workerIdx, dstIP)
		default:
			// Channel full - drop packet (backpressure)
			log.Debug("SharedTUN: worker %d channel full, dropping packet for %s", workerIdx, dstIP)
		}
	}
}

// packetWorker processes packets for a subset of clients
func (st *SharedTUN) packetWorker(id int, ch chan *tunPacket) {
	defer st.wg.Done()

	for {
		select {
		case <-st.stopCh:
			return
		case pkt, ok := <-ch:
			if !ok {
				return
			}

			st.clientsMu.RLock()
			writer, exists := st.clients[pkt.dstIP]
			st.clientsMu.RUnlock()

			if !exists {
				log.Debug("SharedTUN: worker %d: no client for dst=%s, dropping", id, pkt.dstIP)
				continue
			}

			log.Debug("SharedTUN: worker %d: sending %d bytes to %s", id, len(pkt.data), pkt.dstIP)
			if err := writer.SendPacket(pkt.data); err != nil {
				log.Debug("SharedTUN: worker %d: send error to %s: %v", id, pkt.dstIP, err)
			} else {
				log.Debug("SharedTUN: worker %d: sent OK to %s", id, pkt.dstIP)
			}
		}
	}
}

// SendPacket sends a packet to the client connection
func (w *ClientWriter) SendPacket(pkt []byte) error {
	// Check if done
	select {
	case <-w.done:
		return nil // Silently ignore, client disconnected
	default:
	}

	// Clamp TCP MSS on SYN/SYN-ACK going to client
	tun.ClampTCPMSS(pkt, tun.DefaultMTU)

	// Frame the packet according to protocol
	var framedPkt []byte
	if w.framePacket != nil {
		framedPkt = w.framePacket(pkt)
	} else {
		// Default framing: [length:4][packet:N]
		framedPkt = make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(framedPkt[:4], uint32(len(pkt)))
		copy(framedPkt[4:], pkt)
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := w.conn.Write(framedPkt)
	if err != nil {
		return err
	}

	atomic.StoreInt64(&w.lastActive, time.Now().Unix())
	return nil
}

// UpdateActivity updates the last activity timestamp
func (w *ClientWriter) UpdateActivity() {
	atomic.StoreInt64(&w.lastActive, time.Now().Unix())
}

// Done returns the done channel for checking if client is disconnected
func (w *ClientWriter) Done() <-chan struct{} {
	return w.done
}

// CleanupInactiveClients removes clients that have been inactive for too long
func (st *SharedTUN) CleanupInactiveClients(maxInactivity time.Duration) int {
	now := time.Now().Unix()
	maxSec := int64(maxInactivity.Seconds())
	cleaned := 0

	st.clientsMu.Lock()
	defer st.clientsMu.Unlock()

	for ip, writer := range st.clients {
		lastActive := atomic.LoadInt64(&writer.lastActive)
		if now-lastActive > maxSec {
			select {
			case <-writer.done:
				// Already closed
			default:
				close(writer.done)
			}
			delete(st.clients, ip)
			cleaned++
			log.Info("SharedTUN: cleaned inactive client %s (clientID=%s, inactive=%ds)",
				ip, writer.clientID, now-lastActive)
		}
	}

	return cleaned
}

// StartCleanupRoutine starts a background goroutine to clean up inactive clients
func (st *SharedTUN) StartCleanupRoutine(interval, maxInactivity time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-st.stopCh:
				return
			case <-ticker.C:
				if cleaned := st.CleanupInactiveClients(maxInactivity); cleaned > 0 {
					log.Info("SharedTUN: cleanup removed %d inactive clients", cleaned)
				}
			}
		}
	}()
}

// ClientCount returns the number of registered clients
func (st *SharedTUN) ClientCount() int {
	st.clientsMu.RLock()
	defer st.clientsMu.RUnlock()
	return len(st.clients)
}

// Close shuts down the shared TUN and all workers
func (st *SharedTUN) Close() error {
	if !atomic.CompareAndSwapInt32(&st.running, 1, 0) {
		return nil // Already closed
	}

	log.Info("SharedTUN: shutting down %s", st.name)

	// Signal stop
	close(st.stopCh)

	// Close all worker channels
	for i := range st.workerChans {
		close(st.workerChans[i])
	}

	// Close all client connections
	st.clientsMu.Lock()
	for ip, writer := range st.clients {
		select {
		case <-writer.done:
		default:
			close(writer.done)
		}
		delete(st.clients, ip)
	}
	st.clientsMu.Unlock()

	// Close TUN device
	err := st.tunDev.Close()

	// Wait for workers to finish
	st.wg.Wait()

	log.Info("SharedTUN: shutdown complete")
	return err
}

// hashIP creates a simple hash from IP string for worker distribution
func hashIP(ip string) int {
	var h int
	for _, c := range ip {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}
