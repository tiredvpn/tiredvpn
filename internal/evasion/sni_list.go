package evasion

import (
	"fmt"
	"strings"
)

// NormalizeSNI checks that h can stand as a TLS server name in a ClientHello
// and returns it lower-cased. It rejects what would split a list or smuggle a
// port or a path in: commas, colons, slashes, whitespace, and the empty name.
func NormalizeSNI(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" || strings.ContainsAny(h, ",:/ \t") {
		return "", fmt.Errorf("%q is not a hostname", h)
	}
	return strings.ToLower(h), nil
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
