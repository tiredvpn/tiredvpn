package evasion

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeSNI checks that h can stand as a TLS server name in a ClientHello
// and returns it lower-cased: a DNS host name of ASCII letters, digits and
// hyphens (IDNs in their xn-- form), labels of 1-63 characters that neither
// start nor end with a hyphen, 253 characters at most, with no trailing dot
// (RFC 6066 section 3). That leaves out what would split a list or smuggle a
// port or a path in, and what is not a name at all: a wildcard, a control
// character, an IP literal - crypto/tls sends no SNI for an IP, so a pool
// with one would make Stego and QUIC send none - or a top-level label of
// digits only.
func NormalizeSNI(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || len(h) > 253 || net.ParseIP(strings.Trim(h, "[]")) != nil {
		return "", fmt.Errorf("%q is not a hostname", h)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.ContainsFunc(l, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' }) {
			return "", fmt.Errorf("%q is not a hostname", h)
		}
	}
	if tld := labels[len(labels)-1]; !strings.ContainsFunc(tld, func(r rune) bool { return r < '0' || r > '9' }) {
		return "", fmt.Errorf("%q is not a hostname", h)
	}
	return h, nil
}

// ParseSNIList parses a comma-separated hostname list (the -reality-sni flag),
// dropping duplicates and keeping the order given. Empty input is an empty
// list.
func ParseSNIList(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		h, err := NormalizeSNI(part)
		if err != nil {
			return nil, err
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out, nil
}
