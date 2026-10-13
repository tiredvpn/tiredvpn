package main

import (
	"net/url"
	"strings"
	"testing"
)

// TestConnectionStringQUICPort: the admin commands used to write quicPort=8443
// into every connection string by default, a port no server listens on. The
// Android app passes it straight back as -quic-port. It is now written only
// when the operator sets one.
func TestConnectionStringQUICPort(t *testing.T) {
	query := func(s string) url.Values {
		t.Helper()
		_, q, ok := strings.Cut(s, "?")
		if !ok {
			t.Fatalf("no query in %q", s)
		}
		v, err := url.ParseQuery(q)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return v
	}

	if q := query(buildConnectionString("vpn.example.com:995", "s", true, 0, "auto", "c")); q.Has("quicPort") {
		t.Errorf("unset -quic-port wrote quicPort=%s", q.Get("quicPort"))
	}
	if got := query(buildConnectionString("vpn.example.com:995", "s", true, 995, "auto", "c")).Get("quicPort"); got != "995" {
		t.Errorf("explicit -quic-port 995 wrote quicPort=%q", got)
	}
}
