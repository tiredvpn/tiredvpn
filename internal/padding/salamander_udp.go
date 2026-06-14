package padding

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// SalamanderPacketConn wraps a UDP PacketConn with Salamander padding
// Used for QUIC obfuscation - encrypts each UDP packet independently
type SalamanderPacketConn struct {
	net.PacketConn
	padder *SalamanderPadder
	mu     sync.Mutex
}

// NewSalamanderPacketConn creates a Salamander-wrapped PacketConn
func NewSalamanderPacketConn(conn net.PacketConn, padder *SalamanderPadder) *SalamanderPacketConn {
	return &SalamanderPacketConn{
		PacketConn: conn,
		padder:     padder,
	}
}

// ReadFrom reads a packet and decrypts it with Salamander
func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read encrypted packet from underlying connection
	buf := make([]byte, 65536) // Max UDP packet size
	n, addr, err = s.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	encrypted := buf[:n]

	// Decrypt with Salamander (tag-verified UDP framing)
	s.mu.Lock()
	payload, ok := s.padder.DecryptUDP(encrypted)
	s.mu.Unlock()

	if !ok {
		return 0, addr, fmt.Errorf("salamander: packet failed secret verification")
	}

	n = copy(p, payload)
	return n, addr, nil
}

// WriteTo encrypts a packet with Salamander and writes it
func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("salamander: payload too large (%d > 65535)", len(p))
	}

	// Encrypt with Salamander (tag-verified UDP framing)
	s.mu.Lock()
	encrypted, err := s.padder.EncryptUDP(p)
	s.mu.Unlock()

	if err != nil {
		return 0, err
	}

	// Write encrypted packet to underlying connection
	_, err = s.PacketConn.WriteTo(encrypted, addr)
	if err != nil {
		return 0, err
	}

	// Return original payload length
	return len(p), nil
}

// Close closes the underlying connection
func (s *SalamanderPacketConn) Close() error {
	return s.PacketConn.Close()
}

// LocalAddr returns the local network address
func (s *SalamanderPacketConn) LocalAddr() net.Addr {
	return s.PacketConn.LocalAddr()
}

// SetDeadline sets read and write deadlines
func (s *SalamanderPacketConn) SetDeadline(t time.Time) error {
	return s.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (s *SalamanderPacketConn) SetReadDeadline(t time.Time) error {
	return s.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (s *SalamanderPacketConn) SetWriteDeadline(t time.Time) error {
	return s.PacketConn.SetWriteDeadline(t)
}

// GetPadder returns the underlying padder (for level adjustments)
func (s *SalamanderPacketConn) GetPadder() *SalamanderPadder {
	return s.padder
}

// SetPaddingLevel adjusts padding level at runtime
func (s *SalamanderPacketConn) SetPaddingLevel(level PaddingLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.padder.SetLevel(level)
}
