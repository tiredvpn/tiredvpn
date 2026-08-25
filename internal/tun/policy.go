package tun

import "fmt"

// IPv6Policy selects how the client treats IPv6 inside the tunnel.
//
// The zero value is IPv6PolicyOff, which is the historical behavior: the TUN
// interface is IPv4-only (disable_ipv6=1 on Linux) and no v6 traffic enters
// the tunnel.
type IPv6Policy int

const (
	// IPv6PolicyOff keeps the tunnel IPv4-only (default).
	IPv6PolicyOff IPv6Policy = iota
	// IPv6PolicyDual negotiates dual-stack with the exit (handshake version
	// 0x04) and, when the exit agrees, routes IPv6 through the tunnel.
	IPv6PolicyDual
)

// String renders the policy as its CLI value.
func (p IPv6Policy) String() string {
	switch p {
	case IPv6PolicyDual:
		return "dual"
	default:
		return "off"
	}
}

// ParseIPv6Policy parses the -tun-ipv6 flag value. It accepts exactly "off"
// and "dual" today; the accepted set is intentionally a closed list so a
// future "block" value (kill-switch for v6 outside the tunnel) slots in as a
// third case without changing the flag's shape.
func ParseIPv6Policy(s string) (IPv6Policy, error) {
	switch s {
	case "off":
		return IPv6PolicyOff, nil
	case "dual":
		return IPv6PolicyDual, nil
	default:
		return IPv6PolicyOff, fmt.Errorf("invalid IPv6 policy %q: must be one of: off, dual", s)
	}
}
