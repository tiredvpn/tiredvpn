package strategy

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSessionCache records the keys crypto/tls asks for.
type recordingSessionCache struct {
	mu   sync.Mutex
	gets []string
}

func (c *recordingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	c.gets = append(c.gets, key)
	c.mu.Unlock()
	return nil, false
}

func (c *recordingSessionCache) Put(string, *tls.ClientSessionState) {}

func (c *recordingSessionCache) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.gets...)
}

// TestTLSSessionsAreKeptPerServer is P3-17 of the round-3 review of PR #127.
// The stdlib-TLS strategies shared one session cache keyed by ServerName, and
// the cover names are shared between servers - one SNI pool on two exits, the
// fixed hosts of WS, Geneva and anti-probe - so a ticket from server A was
// offered to server B: the same ticket bytes to two addresses. Every
// strategy's ClientHello is built here against a server that answers one
// byte and hangs up, and the cache must be asked under that server's address.
// IMAP, which waits for a greeting before its TLS, is checked on its config.
func TestTLSSessionsAreKeptPerServer(t *testing.T) {
	secret := []byte("session-scope-secret")
	for _, tc := range []struct {
		name string
		make func(m *Manager) Strategy
	}{
		{"HTTP/2 Stego", func(m *Manager) Strategy { return NewHTTP2StegoStrategy(m, secret, "") }},
		{"WebSocket padded", func(m *Manager) Strategy { return NewWebSocketPaddedStrategy(m, secret) }},
		{"Geneva", func(m *Manager) Strategy { return NewGenevaStrategy(m, secret, "ru") }},
		{"anti-probe", func(m *Manager) Strategy { return NewAntiProbeStrategy(m, secret) }},
		{"Traffic Morph", func(m *Manager) Strategy { return NewTrafficMorphStrategy(m, YandexVideoProfile, nil, secret) }},
		{"State Exhaustion", func(m *Manager) Strategy { return NewStateExhaustionStrategy(m, secret) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			silent := newHelloListener(t)
			m := newSilenceManager(t, 2*time.Second, silent.addr)
			rec := &recordingSessionCache{}
			m.tlsSessionCache = rec
			s := tc.make(m)
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			if conn, err := s.Connect(m.withDialCandidate(ctx, m.selector().Candidates()[0]), silent.addr); err == nil {
				conn.Close()
			}
			keys := rec.keys()
			if len(keys) == 0 {
				t.Fatal("no TLS ClientHello was built - the test proves nothing")
			}
			for _, k := range keys {
				if !strings.HasPrefix(k, silent.addr+"\x00") {
					t.Fatalf("session looked up as %q, not under the server %s", k, silent.addr)
				}
			}
		})
	}
}

func TestIMAPTLSSessionsAreKeptPerServer(t *testing.T) {
	m := NewManager()
	rec := &recordingSessionCache{}
	m.tlsSessionCache = rec
	cfg := NewIMAPCamouflageStrategy(m, []byte("s")).clientTLSConfig("203.0.113.10:993")
	cfg.ClientSessionCache.Get("imap.example")
	if keys := rec.keys(); len(keys) != 1 || keys[0] != "203.0.113.10:993\x00imap.example" {
		t.Fatalf("IMAP looked its session up as %q", keys)
	}
}
