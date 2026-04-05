package evasion

import (
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// QUICReassemblyPacketConn wraps net.PacketConn with UDP fragment reassembly
// This is the server-side counterpart to QUICFragmentPacketConn
// It reassembles fragmented UDP datagrams back into complete QUIC packets
type QUICReassemblyPacketConn struct {
	net.PacketConn

	mu             sync.Mutex
	sessions       map[string]*reassemblySession // key: fragID (4 bytes as string)
	sessionTimeout time.Duration
}

// reassemblySession tracks fragments for reassembly
type reassemblySession struct {
	fragID       [4]byte
	fragments    map[int][]byte // seq -> data
	totalFrags   int
	received     int
	lastActivity time.Time
	srcAddr      net.Addr
}

// ReassemblyConfig configures reassembly behavior
type ReassemblyConfig struct {
	SessionTimeout time.Duration
	MaxSessions    int
}

// DefaultReassemblyConfig returns sensible defaults
func DefaultReassemblyConfig() *ReassemblyConfig {
	return &ReassemblyConfig{
		SessionTimeout: 5 * time.Second,
		MaxSessions:    1000,
	}
}

// NewQUICReassemblyPacketConn wraps a PacketConn with fragment reassembly
func NewQUICReassemblyPacketConn(conn net.PacketConn, config *ReassemblyConfig) *QUICReassemblyPacketConn {
	if config == nil {
		config = DefaultReassemblyConfig()
	}

	rc := &QUICReassemblyPacketConn{
		PacketConn:     conn,
		sessions:       make(map[string]*reassemblySession),
		sessionTimeout: config.SessionTimeout,
	}

	// Start cleanup goroutine
	go rc.cleanupLoop()

	return rc
}

// ReadFrom reads a packet, reassembling fragments if needed
func (c *QUICReassemblyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		// Read from underlying connection
		buf := make([]byte, 2000) // max UDP datagram
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		buf = buf[:n]

		// Check if this is a fragment (starts with magic)
		if n >= fragHeaderSize && buf[0] == fragMagic1 && buf[1] == fragMagic2 {
			// Parse fragment header
			seq := int(buf[2])<<8 | int(buf[3])
			total := int(buf[4])<<8 | int(buf[5])
			var fragID [4]byte
			copy(fragID[:], buf[6:10])
			data := buf[fragHeaderSize:]

			log.Debug("Received fragment %d/%d for fragID %x, size=%d", seq+1, total, fragID, len(data))

			// Get or create session
			c.mu.Lock()
			sessionKey := string(fragID[:])
			session, exists := c.sessions[sessionKey]
			if !exists {
				session = &reassemblySession{
					fragID:       fragID,
					fragments:    make(map[int][]byte),
					totalFrags:   total,
					lastActivity: time.Now(),
					srcAddr:      addr,
				}
				c.sessions[sessionKey] = session
			}

			// Add fragment
			if _, dup := session.fragments[seq]; !dup {
				session.fragments[seq] = make([]byte, len(data))
				copy(session.fragments[seq], data)
				session.received++
			}
			session.lastActivity = time.Now()

			// Check if complete
			if session.received >= session.totalFrags {
				// Reassemble
				assembled := c.assembleFragments(session)
				delete(c.sessions, sessionKey)
				c.mu.Unlock()

				log.Debug("Reassembled %d fragments into %d byte packet", session.totalFrags, len(assembled))

				if len(assembled) > len(p) {
					assembled = assembled[:len(p)]
				}
				copy(p, assembled)
				return len(assembled), session.srcAddr, nil
			}

			c.mu.Unlock()
			// Continue reading more fragments
			continue
		}

		// Not a fragment - pass through directly
		copy(p, buf)
		return n, addr, nil
	}
}

// assembleFragments combines all fragments in order
func (c *QUICReassemblyPacketConn) assembleFragments(session *reassemblySession) []byte {
	// Calculate total size
	totalSize := 0
	for _, data := range session.fragments {
		totalSize += len(data)
	}

	// Assemble in order
	result := make([]byte, 0, totalSize)
	for i := 0; i < session.totalFrags; i++ {
		if data, ok := session.fragments[i]; ok {
			result = append(result, data...)
		}
	}

	return result
}

// WriteTo passes through to underlying connection (no fragmentation on server side)
func (c *QUICReassemblyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, addr)
}

// cleanupLoop removes stale reassembly sessions
func (c *QUICReassemblyPacketConn) cleanupLoop() {
	ticker := time.NewTicker(c.sessionTimeout / 2)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, session := range c.sessions {
			if now.Sub(session.lastActivity) > c.sessionTimeout {
				log.Debug("Reassembly session timeout for fragID %x (received %d/%d)",
					session.fragID, session.received, session.totalFrags)
				delete(c.sessions, key)
			}
		}
		c.mu.Unlock()
	}
}

// LocalAddr returns the local address
func (c *QUICReassemblyPacketConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

// Close closes the connection
func (c *QUICReassemblyPacketConn) Close() error {
	return c.PacketConn.Close()
}

// SetDeadline sets deadline
func (c *QUICReassemblyPacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *QUICReassemblyPacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *QUICReassemblyPacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

// Ensure interface compliance
var _ net.PacketConn = (*QUICReassemblyPacketConn)(nil)
