package tun

import "fmt"

// IPv6Policy selects how the client treats IPv6 while the tunnel is up.
//
// The zero value is IPv6PolicyOff, which is the historical behavior: the TUN
// interface is IPv4-only (disable_ipv6=1 on Linux), no v6 traffic enters the
// tunnel, and the host's own IPv6 is left alone — which on a dual-stack host
// means applications reach the internet over IPv6 outside the VPN.
type IPv6Policy int

const (
	// IPv6PolicyOff keeps the tunnel IPv4-only and does not touch host IPv6.
	IPv6PolicyOff IPv6Policy = iota
	// IPv6PolicyDual negotiates dual-stack with the exit (handshake version
	// 0x04) and, when the exit agrees, routes IPv6 through the tunnel. When
	// the exit declines — an old exit, or one with no -ip-pool-v6 — outbound
	// IPv6 is blocked instead, so it cannot leave outside the tunnel. This is
	// the default.
	IPv6PolicyDual
	// IPv6PolicyBlock never asks for IPv6 inside the tunnel (the handshake
	// version stays 0x03, byte-identical to a v4-only client) and blocks
	// outbound IPv6 for the life of the tunnel. The kill-switch without the
	// negotiation.
	IPv6PolicyBlock
)

// Accepted -tun-ipv6 values.
const (
	ipv6PolicyOffValue   = "off"
	ipv6PolicyDualValue  = "dual"
	ipv6PolicyBlockValue = "block"
)

// DefaultIPv6Policy is the -tun-ipv6 value that applies when the flag is not
// set. IPv6 goes into the tunnel by default (issue #55: on a dual-stack host a
// v4-only tunnel is bypassed by every application with a working v6 default
// route), falling back to blocking it when the exit cannot carry it.
const DefaultIPv6Policy = ipv6PolicyDualValue

// String renders the policy as its CLI value.
func (p IPv6Policy) String() string {
	switch p {
	case IPv6PolicyDual:
		return ipv6PolicyDualValue
	case IPv6PolicyBlock:
		return ipv6PolicyBlockValue
	default:
		return ipv6PolicyOffValue
	}
}

// NegotiatesDualStack reports whether the policy asks the exit for IPv6 tunnel
// addresses, i.e. whether the handshake version byte is 0x04 rather than 0x03.
// This is the policy's only effect on the wire.
func (p IPv6Policy) NegotiatesDualStack() bool {
	return p == IPv6PolicyDual
}

// BlocksLeakedIPv6 reports whether outbound IPv6 that did not make it into the
// tunnel must be rejected. True for the dual policy (as the fallback when the
// exit declined dual-stack) and for the block policy (always).
func (p IPv6Policy) BlocksLeakedIPv6() bool {
	return p == IPv6PolicyDual || p == IPv6PolicyBlock
}

// ipv6Action is what the client does about IPv6 once the handshake has told it
// whether the exit will carry IPv6. Split out of connect() so the decision can
// be exercised without a network, a TUN or root.
type ipv6Action int

const (
	// ipv6ActionNone leaves both the tunnel and the host's IPv6 alone: the
	// policy is off, or the interface belongs to the host (Android
	// VpnService / macOS NE), which does its own routing and filtering.
	ipv6ActionNone ipv6Action = iota
	// ipv6ActionEnableDual installs the negotiated v6 address and routes.
	ipv6ActionEnableDual
	// ipv6ActionBlock rejects outbound IPv6: either the exit declined
	// dual-stack, or the policy never asked for it.
	ipv6ActionBlock
)

// ipv6ActionFor resolves the post-handshake IPv6 decision. negotiated is
// whether the exit actually returned dual-stack addresses.
func ipv6ActionFor(policy IPv6Policy, ownsInterface, negotiated bool) ipv6Action {
	if !ownsInterface {
		return ipv6ActionNone
	}
	switch policy {
	case IPv6PolicyBlock:
		return ipv6ActionBlock
	case IPv6PolicyDual:
		if negotiated {
			return ipv6ActionEnableDual
		}
		// The exit cannot carry IPv6. Leaving the host's v6 alone here is
		// what issue #55 is about, so it gets blocked instead.
		return ipv6ActionBlock
	default:
		return ipv6ActionNone
	}
}

// ParseIPv6Policy parses the -tun-ipv6 flag value. The accepted set is a closed
// list of exactly {off, dual, block}; an empty string is rejected rather than
// silently defaulted, so callers have to name the default explicitly
// (DefaultIPv6Policy).
func ParseIPv6Policy(s string) (IPv6Policy, error) {
	switch s {
	case ipv6PolicyOffValue:
		return IPv6PolicyOff, nil
	case ipv6PolicyDualValue:
		return IPv6PolicyDual, nil
	case ipv6PolicyBlockValue:
		return IPv6PolicyBlock, nil
	default:
		return IPv6PolicyOff, fmt.Errorf("invalid IPv6 policy %q: must be one of: %s, %s, %s",
			s, ipv6PolicyOffValue, ipv6PolicyDualValue, ipv6PolicyBlockValue)
	}
}
