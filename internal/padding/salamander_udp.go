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
	frags  *fragReassembler
}

// NewSalamanderPacketConn creates a Salamander-wrapped PacketConn
func NewSalamanderPacketConn(conn net.PacketConn, padder *SalamanderPadder) *SalamanderPacketConn {
	return &SalamanderPacketConn{
		PacketConn: conn,
		padder:     padder,
		frags:      newFragReassembler(),
	}
}

// ReadFrom reads a packet and decrypts it with Salamander.
//
// A datagram that fails the tag check is dropped and the read continues with
// the next one. Returning an error instead would be fatal well beyond the one
// datagram: quic-go's transport read loop treats a read error that is not a
// temporary net.Error as terminal and tears the listener down, so a single
// stray packet sent to the port - a scan, a late datagram from a closed
// session, anything - would take every live connection with it. Only errors
// from the underlying conn, which are the ones that really are about the
// socket, propagate. See TestSalamanderReadFromSurvivesGarbage.
func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, maxUDPPayload+1) // Max UDP packet size
	for {
		n, addr, err = s.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}

		encrypted := buf[:n]

		// Decrypt with Salamander (tag-verified UDP framing)
		s.mu.Lock()
		frame, ok := s.padder.decryptUDPFrame(encrypted)
		s.mu.Unlock()

		if !ok {
			continue
		}

		payload := frame.data
		if frame.frag {
			assembled, complete := s.frags.add(addr.String(), frame)
			if !complete {
				continue
			}
			payload = assembled
		}

		return copy(p, payload), addr, nil
	}
}

// WriteTo encrypts a packet with Salamander and writes it. A payload too large
// to travel under the datagram ceiling is split across several datagrams rather
// than sent unpadded at its exact length.
func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > maxUDPPayload {
		return 0, fmt.Errorf("salamander: payload too large (%d > %d)", len(p), maxUDPPayload)
	}

	// Encrypt with Salamander (tag-verified UDP framing)
	s.mu.Lock()
	datagrams, err := s.padder.EncryptUDPDatagrams(p)
	s.mu.Unlock()

	if err != nil {
		return 0, err
	}

	for _, d := range datagrams {
		if _, err = s.PacketConn.WriteTo(d, addr); err != nil {
			return 0, err
		}
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
