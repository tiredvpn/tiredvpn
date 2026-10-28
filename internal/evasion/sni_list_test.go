package evasion

import "testing"

// TestNormalizeSNIAcceptsOnlyHostNames is P3-13 of the round-3 review of PR
// #127: the check let through what is not a DNS host name - a wildcard, a
// trailing dot, a control character, an IP literal. With an IP in the pool,
// Stego and QUIC send no SNI at all (crypto/tls leaves an IP out of the
// ClientHello), which is a fingerprint of its own.
func TestNormalizeSNIAcceptsOnlyHostNames(t *testing.T) {
	for _, good := range []string{"www.google.com", "WWW.GSTATIC.COM", "a-b.example", "xn--80ak6aa92e.com", "localhost"} {
		if _, err := NormalizeSNI(good); err != nil {
			t.Errorf("%q rejected: %v", good, err)
		}
	}
	long := ""
	for range 64 {
		long += "a"
	}
	for _, bad := range []string{
		"", " ", "*.google.com", "www.google.com.", "www.goo\ngle.com", "www.google.com\x00",
		"203.0.113.10", "2001:db8::1", "[2001:db8::1]", "-lead.example", "trail-.example",
		"a..b", "under_score.example", "пример.рф", long + ".example", "a,b", "a:443", "a/b",
	} {
		if got, err := NormalizeSNI(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
