package padding

import (
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

	// Decrypt with Salamander
	s.mu.Lock()
	decrypted, err := s.padder.Decrypt(encrypted)
	s.mu.Unlock()

	if err != nil {
		return 0, addr, err
	}

	// QUIC packets have 2-byte length prefix for actual data
	if len(decrypted) < 2 {
		// No length prefix - use full decrypted data (backwards compat)
		n = copy(p, decrypted)
		return n, addr, nil
	}

	// Check if this has a length prefix (first 2 bytes)
	// If first 2 bytes look like a reasonable length (< len(decrypted)), use it
	dataLen := int(decrypted[0])<<8 | int(decrypted[1])
	if dataLen > 0 && dataLen <= len(decrypted)-2 {
		// Has length prefix
		actualData := decrypted[2 : 2+dataLen]
		n = copy(p, actualData)
		return n, addr, nil
	}

	// No valid length prefix - use full data
	n = copy(p, decrypted)
	return n, addr, nil
}

// WriteTo encrypts a packet with Salamander and writes it
func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Prepend 2-byte length prefix
	dataWithLen := make([]byte, 2+len(p))
	dataWithLen[0] = byte(len(p) >> 8)
	dataWithLen[1] = byte(len(p))
	copy(dataWithLen[2:], p)

	// Encrypt with Salamander
	s.mu.Lock()
	encrypted, err := s.padder.Encrypt(dataWithLen)
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
