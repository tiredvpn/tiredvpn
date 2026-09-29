//go:build !linux

package ktls

import (
	"crypto/tls"
	"io"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

func init() {
	log.Debug("kTLS: not available on this platform")
}

// Supported returns false on non-Linux platforms
func Supported() bool {
	return false
}

// Enable always returns nil on non-Linux platforms (kTLS not supported)
func Enable(tlsConn *tls.Conn) *Conn {
	return nil
}

// Stats returns zeros on non-Linux platforms
func Stats() (enabled, fallback int64) {
	return 0, 0
}

type recvState struct{}

func (c *Conn) readSocket(b []byte) (int, error) {
	n, err := c.tcpConn.Read(b)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
