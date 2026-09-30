package protocol

import (
	"fmt"
	"net"
	"strconv"
)

// A proxied session opens with the target address framed as
// [len:2 big-endian][host:port]. The server reads the first byte of that frame
// before it knows which mode the session is in: 0x02 means TUN mode, anything
// else is the high byte of the length. A target of 512 bytes or more therefore
// starts with 0x02 or higher and is taken for (or corrupts) a TUN handshake.
//
// The bound below is the SOCKS5 address format, which is what every client
// path builds targets from: a host of at most 255 bytes and a 16-bit port.
const (
	// MaxTargetHostLen is the longest host a SOCKS5 request can carry.
	MaxTargetHostLen = 255

	// MaxTargetLen is the longest valid target: a bracketed IPv6 literal of
	// MaxTargetHostLen bytes plus ":65535". Its high byte is 0x01, so the
	// first byte of a valid frame is always 0x00 or 0x01 and never the 0x02
	// TUN-mode marker.
	MaxTargetLen = 1 + MaxTargetHostLen + 1 + 1 + 5
)

// ValidateTarget reports whether addr can be sent as a length-prefixed target
// without the prefix colliding with a session-mode byte. It accepts exactly
// what the SOCKS5 address format can express: host:port or [host]:port with a
// host of at most MaxTargetHostLen bytes and a decimal port of at most five
// digits in the range 0-65535.
func ValidateTarget(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	if len(host) > MaxTargetHostLen {
		return fmt.Errorf("target host too long: %d bytes, max %d", len(host), MaxTargetHostLen)
	}
	// ParseUint takes no sign or digit separators in base 10; the length cap
	// rules out leading zeros stretching the target.
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || len(port) > 5 {
		return fmt.Errorf("invalid target port %q", port)
	}
	return nil
}
