package endpoint

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// This file is the one place a configured server address becomes the
// "host:port" string the dialer gets. Every source of addresses - the
// [[servers]] list, a lone [server], the -server/-server-v6 flags, the JNI
// argv - goes through it, so a single server and a pool of N cannot disagree
// about the form of the same input.
//
// The form matters because nothing below this layer repairs it: a bare IPv6
// literal handed to net.Dial fails with "too many colons", the connectivity
// gate cannot split it, and the client sits in "No TCP connectivity" forever.

// SplitAddr parses a configured address into host and port. It accepts
//
//	host:port, [v6]:port   - the dial form
//	host, v4               - no port
//	[v6], v6               - no port; a bare IPv6 literal cannot carry one, so
//	                         "2001:db8::2:995" is the address 2001:db8::2:995
//
// port is 0 when the input names none. The host comes back unbracketed.
func SplitAddr(raw string) (host string, port int, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, errors.New("empty address")
	}
	if h, p, splitErr := net.SplitHostPort(s); splitErr == nil {
		if h == "" {
			return "", 0, fmt.Errorf("address %q: missing host", raw)
		}
		n, err := parsePort(p)
		if err != nil {
			return "", 0, fmt.Errorf("address %q: %w", raw, err)
		}
		return h, n, nil
	}

	// No port. What is left must be a host on its own.
	if inner, ok := strings.CutPrefix(s, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		if !ok || !isIPv6Literal(inner) {
			return "", 0, fmt.Errorf("address %q: malformed bracketed IPv6 address", raw)
		}
		return inner, 0, nil
	}
	if strings.Contains(s, ":") {
		if isIPv6Literal(s) {
			return s, 0, nil
		}
		return "", 0, fmt.Errorf("address %q: neither host:port nor an IPv6 address", raw)
	}
	if strings.ContainsAny(s, "[]/ \t") {
		return "", 0, fmt.Errorf("address %q: invalid host", raw)
	}
	return s, 0, nil
}

// JoinAddr is the dial form of host and port: IPv6 bracketed, everything else
// as is. host must already be unbracketed, which is what SplitAddr returns.
func JoinAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// NormalizeAddr turns a configured address into the dial form, using
// defaultPort when the address names no port of its own. A port in the address
// wins over defaultPort. An empty address stays empty: "no address on this
// family" is a legal configuration.
func NormalizeAddr(raw string, defaultPort int) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	host, port, err := SplitAddr(raw)
	if err != nil {
		return "", err
	}
	if port == 0 {
		if defaultPort == 0 {
			return "", fmt.Errorf("address %q has no port", raw)
		}
		if _, err := parsePort(strconv.Itoa(defaultPort)); err != nil {
			return "", fmt.Errorf("address %q: default %w", raw, err)
		}
		port = defaultPort
	}
	return JoinAddr(host, port), nil
}

// NormalizePair normalizes one server's two addresses. A family that names no
// port takes the other family's: the normal deployment listens on one port on
// both, which is also what port_v6 defaulting to port says in the config file
// and what the Android app assumes when it builds a pool entry.
func NormalizePair(v4, v6 string) (string, string, error) {
	p4 := explicitPort(v4)
	p6 := explicitPort(v6)
	n4, err := NormalizeAddr(v4, p6)
	if err != nil {
		return "", "", err
	}
	n6, err := NormalizeAddr(v6, p4)
	if err != nil {
		return "", "", err
	}
	return n4, n6, nil
}

// Normalized returns e with both addresses in the dial form. It is idempotent,
// so an endpoint that is already normal comes back unchanged.
func (e Endpoint) Normalized() (Endpoint, error) {
	v4, v6, err := NormalizePair(e.V4, e.V6)
	if err != nil {
		return Endpoint{}, err
	}
	e.V4, e.V6 = v4, v6
	return e, nil
}

// explicitPort is the port raw names itself, or 0.
func explicitPort(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	_, port, err := SplitAddr(raw)
	if err != nil {
		return 0
	}
	return port
}

func parsePort(p string) (int, error) {
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", p)
	}
	return int(n), nil
}

func isIPv6Literal(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6()
}
