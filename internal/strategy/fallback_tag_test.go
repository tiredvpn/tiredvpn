package strategy

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// rawHelloCatcher is a listener that keeps the first TLS record of every
// connection - the ClientHello as it left the client - and hangs up.
type rawHelloCatcher struct {
	addr string
	mu   sync.Mutex
	got  [][]byte
}

func newRawHelloCatcher(t *testing.T) *rawHelloCatcher {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &rawHelloCatcher{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x16 {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				c.mu.Lock()
				c.got = append(c.got, body)
				c.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *rawHelloCatcher) hellos() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.got...)
}

// fallbackTLSStrategies are the transports that open with a plain crypto/tls
// ClientHello on the server's port, so a B1 gate sees their first flight.
var fallbackTLSStrategies = []struct {
	name string
	make func(m *Manager, secret []byte) Strategy
}{
	{"HTTP Polling", func(m *Manager, s []byte) Strategy { return NewHTTPPollingStrategy(m, s) }},
	{"WebSocket padded", func(m *Manager, s []byte) Strategy { return NewWebSocketPaddedStrategy(m, s) }},
	{"Geneva", func(m *Manager, s []byte) Strategy { return NewGenevaStrategy(m, s, "ru") }},
	{"anti-probe", func(m *Manager, s []byte) Strategy { return NewAntiProbeStrategy(m, s) }},
	{"HTTP/2 Stego", func(m *Manager, s []byte) Strategy { return NewHTTP2StegoStrategy(m, s, "") }},
	{"Traffic Morph", func(m *Manager, s []byte) Strategy { return NewTrafficMorphStrategy(m, YandexVideoProfile, nil, s) }},
	{"State Exhaustion", func(m *Manager, s []byte) Strategy { return NewStateExhaustionStrategy(m, s) }},
	// With ECH they dial twice: the ECH attempt, then a plain retry when the
	// server does not take it. Each of the two needs its own tag.
	{"HTTP/2 Stego ECH", func(m *Manager, s []byte) Strategy {
		return NewHTTP2StegoStrategyWithECH(m, s, "", testECHConfigList, "cloudflare-ech.com")
	}},
	{"anti-probe ECH", func(m *Manager, s []byte) Strategy {
		a := NewAntiProbeStrategy(m, s)
		a.SetECH(testECHConfigList, "cloudflare-ech.com")
		return a
	}},
}

// testECHConfigList is a well-formed ECH config (draft-ietf-tls-esni-18,
// X25519 / HKDF-SHA256 / AES-128-GCM) that the listener cannot decrypt.
var testECHConfigList = func() []byte {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	pub := priv.PublicKey().Bytes()
	body := []byte{7}        // config_id
	body = u16(body, 0x0020) // KEM: DHKEM(X25519, HKDF-SHA256)
	body = u16(body, len(pub))
	body = append(body, pub...)
	body = u16(body, 4)
	body = u16(body, 0x0001) // KDF: HKDF-SHA256
	body = u16(body, 0x0001) // AEAD: AES-128-GCM
	body = append(body, 0)   // maximum_name_length
	name := "cloudflare-ech.com"
	body = append(body, byte(len(name)))
	body = append(body, name...)
	body = u16(body, 0) // extensions
	cfg := u16(u16(nil, 0xfe0d), len(body))
	cfg = append(cfg, body...)
	return append(u16(nil, len(cfg)), cfg...)
}()

// TestFallbackTransportsTagTheirClientHello reads the ClientHello each TLS
// fallback transport puts on the socket and checks its session_id is a tag of
// the endpoint's secret - not of the one the strategy was built with, which
// the control below must reject, or the test could not tell them apart.
func TestFallbackTransportsTagTheirClientHello(t *testing.T) {
	dialKey := customtls.DeriveFallbackTagKey([]byte(wireDialSecret))
	builtKey := customtls.DeriveFallbackTagKey([]byte(wireBuiltSecret))
	for _, tc := range fallbackTLSStrategies {
		t.Run(tc.name, func(t *testing.T) {
			catcher := newRawHelloCatcher(t)
			m := managerAt(t, catcher.addr)
			s := tc.make(m, []byte(wireBuiltSecret))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if conn, err := s.Connect(m.withDialCandidate(ctx, m.selector().Candidates()[0]), catcher.addr); err == nil {
				conn.Close()
			}
			hellos := catcher.hellos()
			want := 1
			if strings.HasSuffix(tc.name, " ECH") {
				want = 2
			}
			if len(hellos) < want {
				t.Fatalf("%d ClientHello reached the listener, want %d - the test proves nothing", len(hellos), want)
			}
			if want == 2 && !bytes.Contains(hellos[0], []byte{0xfe, 0x0d}) {
				t.Fatal("the first hello carries no ECH extension - the ECH dial was not exercised")
			}
			for i, hello := range hellos {
				sid, err := customtls.SessionIDFrom(hello)
				if err != nil {
					t.Fatalf("hello %d: %v", i, err)
				}
				if _, ok := builtKey.Open(sid); ok {
					t.Fatalf("hello %d is tagged with the strategy's own secret, not the endpoint's", i)
				}
				if _, ok := dialKey.Open(sid); !ok {
					t.Fatalf("hello %d: session_id is not a tag of the endpoint's secret", i)
				}
			}
		})
	}
}
