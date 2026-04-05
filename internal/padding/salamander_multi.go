package padding

import (
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// SecretProvider returns a list of secrets to try for decryption
type SecretProvider func() [][]byte

// MultiSecretSalamanderPacketConn wraps a UDP PacketConn with Salamander padding
// that supports multiple secrets for decryption (for per-client secrets support)
type MultiSecretSalamanderPacketConn struct {
	net.PacketConn
	globalPadder   *SalamanderPadder
	globalSecret   []byte
	secretProvider SecretProvider
	level          PaddingLevel
	mu             sync.Mutex

	// Cache padders for efficiency
	padderCache map[string]*SalamanderPadder

	// Track which secret was used per remote address
	// Key: remote addr string, Value: secret bytes
	addrSecrets map[string][]byte
}

// NewMultiSecretSalamanderPacketConn creates a Salamander-wrapped PacketConn
// that supports multiple secrets for decryption
func NewMultiSecretSalamanderPacketConn(conn net.PacketConn, globalSecret []byte, level PaddingLevel, provider SecretProvider) *MultiSecretSalamanderPacketConn {
	return &MultiSecretSalamanderPacketConn{
		PacketConn:     conn,
		globalPadder:   NewSalamanderPadder(globalSecret, level),
		globalSecret:   globalSecret,
		secretProvider: provider,
		level:          level,
		padderCache:    make(map[string]*SalamanderPadder),
		addrSecrets:    make(map[string][]byte),
	}
}

// getPadder returns a padder for the given secret (cached)
func (s *MultiSecretSalamanderPacketConn) getPadder(secret []byte) *SalamanderPadder {
	key := string(secret)
	if padder, ok := s.padderCache[key]; ok {
		return padder
	}
	padder := NewSalamanderPadder(secret, s.level)
	s.padderCache[key] = padder
	return padder
}

// tryDecrypt attempts to decrypt with a specific padder
// Returns decrypted data and true if successful, nil and false otherwise
func (s *MultiSecretSalamanderPacketConn) tryDecrypt(padder *SalamanderPadder, encrypted []byte) ([]byte, bool) {
	decrypted, err := padder.Decrypt(encrypted)
	if err != nil {
		return nil, false
	}

	// Check if decrypted data looks valid (has valid length prefix)
	if len(decrypted) < 2 {
		return nil, false
	}

	dataLen := int(decrypted[0])<<8 | int(decrypted[1])
	if dataLen > 0 && dataLen <= len(decrypted)-2 && dataLen < 65000 {
		// Valid QUIC packet with length prefix
		return decrypted, true
	}

	// Also check if it looks like a QUIC long header (for initial packets)
	// QUIC long header starts with 1xxx xxxx (high bit set)
	if len(decrypted) >= 5 && (decrypted[0]&0x80) != 0 {
		// Could be a QUIC packet without our length prefix (shouldn't happen but check anyway)
		return decrypted, true
	}

	return nil, false
}

// ReadFrom reads a packet and decrypts it with Salamander
// Tries global secret first, then per-client secrets
// Tracks which secret worked for each address to use on responses
func (s *MultiSecretSalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read encrypted packet from underlying connection
	buf := make([]byte, 65536)
	n, addr, err = s.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	encrypted := buf[:n]
	addrStr := addr.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	// 0. Check if we already know this address's secret
	if knownSecret, ok := s.addrSecrets[addrStr]; ok {
		padder := s.getPadder(knownSecret)
		if decrypted, ok := s.tryDecrypt(padder, encrypted); ok {
			return s.extractData(decrypted, p), addr, nil
		}
		// Secret didn't work - client might have changed, continue trying others
	}

	// 1. Try global secret first (most common case)
	if decrypted, ok := s.tryDecrypt(s.globalPadder, encrypted); ok {
		s.addrSecrets[addrStr] = s.globalSecret
		return s.extractData(decrypted, p), addr, nil
	}

	// 2. Try per-client secrets
	if s.secretProvider != nil {
		secrets := s.secretProvider()
		for _, secret := range secrets {
			padder := s.getPadder(secret)
			if decrypted, ok := s.tryDecrypt(padder, encrypted); ok {
				log.Debug("QUIC Salamander: decrypted with client secret for %s", addrStr)
				s.addrSecrets[addrStr] = secret // Remember for responses
				return s.extractData(decrypted, p), addr, nil
			}
		}
	}

	// 3. Fallback: try global decryption without validation
	// This handles edge cases and backwards compatibility
	decrypted, err := s.globalPadder.Decrypt(encrypted)
	if err != nil {
		return 0, addr, err
	}

	s.addrSecrets[addrStr] = s.globalSecret
	return s.extractData(decrypted, p), addr, nil
}

// extractData extracts actual data from decrypted packet (handles length prefix)
func (s *MultiSecretSalamanderPacketConn) extractData(decrypted []byte, p []byte) int {
	if len(decrypted) < 2 {
		return copy(p, decrypted)
	}

	// Check for length prefix
	dataLen := int(decrypted[0])<<8 | int(decrypted[1])
	if dataLen > 0 && dataLen <= len(decrypted)-2 {
		actualData := decrypted[2 : 2+dataLen]
		return copy(p, actualData)
	}

	// No valid length prefix - use full data
	return copy(p, decrypted)
}

// WriteTo encrypts a packet with Salamander and writes it
// Uses the same secret that was used to decrypt packets from this address
func (s *MultiSecretSalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Prepend 2-byte length prefix
	dataWithLen := make([]byte, 2+len(p))
	dataWithLen[0] = byte(len(p) >> 8)
	dataWithLen[1] = byte(len(p))
	copy(dataWithLen[2:], p)

	s.mu.Lock()
	// Find the padder for this address (use global as fallback)
	addrStr := addr.String()
	var padder *SalamanderPadder
	if secret, ok := s.addrSecrets[addrStr]; ok {
		padder = s.getPadder(secret)
	} else {
		padder = s.globalPadder
	}
	encrypted, err := padder.Encrypt(dataWithLen)
	s.mu.Unlock()

	if err != nil {
		return 0, err
	}

	_, err = s.PacketConn.WriteTo(encrypted, addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close closes the underlying connection
func (s *MultiSecretSalamanderPacketConn) Close() error {
	return s.PacketConn.Close()
}

// LocalAddr returns the local network address
func (s *MultiSecretSalamanderPacketConn) LocalAddr() net.Addr {
	return s.PacketConn.LocalAddr()
}

// SetDeadline sets read and write deadlines
func (s *MultiSecretSalamanderPacketConn) SetDeadline(t time.Time) error {
	return s.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (s *MultiSecretSalamanderPacketConn) SetReadDeadline(t time.Time) error {
	return s.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (s *MultiSecretSalamanderPacketConn) SetWriteDeadline(t time.Time) error {
	return s.PacketConn.SetWriteDeadline(t)
}
