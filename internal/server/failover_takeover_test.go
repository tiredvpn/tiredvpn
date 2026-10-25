package server

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"golang.org/x/net/http2"
)

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestSameClientTakeoverIsNotACollision is a P3 of the PR #126 round-2 review:
// every successful strategy upgrade made the exit log "replacing LIVE
// connection ... two clients may be sharing one tunnel IP". A live session
// taken over from the same address under the same lease is the client moving
// its own tunnel; the warning stays for a takeover from another address.
func TestSameClientTakeoverIsNotACollision(t *testing.T) {
	for _, tc := range []struct {
		name  string
		from  string
		warns bool
	}{
		{"same origin", "192.0.2.170", false},
		{"other origin", "198.51.100.152", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &syncBuf{}
			log.SetOutput(out)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			st := newTestSharedTUN(t)
			ip := net.IPv4(10, 8, 0, 2)
			a, a2 := net.Pipe()
			b, b2 := net.Pipe()
			t.Cleanup(func() { a.Close(); a2.Close(); b.Close(); b2.Close() })
			st.RegisterClient(ip, "global@192.0.2.170", &remoteConn{a, &net.TCPAddr{IP: net.ParseIP("192.0.2.170"), Port: 1}}, nil)
			st.RegisterClient(ip, "global@192.0.2.170", &remoteConn{b, &net.TCPAddr{IP: net.ParseIP(tc.from), Port: 2}}, nil)

			if warned := strings.Contains(out.String(), "two clients may be sharing one tunnel IP"); warned != tc.warns {
				t.Fatalf("collision warning=%v, want %v; log:\n%s", warned, tc.warns, out)
			}
		})
	}
}

// pollingTakeover runs runPollingTUNMode for a session from origin until it has
// registered with st, the way processHTTPPollingRequest starts it.
func pollingTakeover(t *testing.T, srvCtx *serverContext, origin string) {
	t.Helper()
	sess := newPollingSession("takeover-" + origin)
	sess.Origin = origin
	sess.ClientID = sharedIdentity("global")
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPollingTUNMode(sess, []byte{10, 99, 0, 9, 0x05, 0x00, 0x03}, srvCtx, testLogger(t))
	}()
	t.Cleanup(func() { sess.Close(); <-done })
	waitRegistered(t, srvCtx.sharedTUN, sess)
}

// h2Takeover runs setupH2TUNTunnel for a stream from origin, as the frame loop
// does after the stego auth.
func h2Takeover(t *testing.T, srvCtx *serverContext, origin string) {
	t.Helper()
	tunnel := &h2TunnelState{streamID: 1, clientID: sharedIdentity("global"), secret: []byte("takeover-test-secret"), remoteAddr: origin}
	framer := http2.NewFramer(io.Discard, bytes.NewReader(nil))
	setupH2TUNTunnel(tunnel, framer, []byte{10, 99, 0, 9, 0x05, 0x00, 0x03}, srvCtx, testLogger(t))
	if tunnel.sharedTUNWriter == nil {
		t.Fatal("H2 tunnel did not register")
	}
}

// waitRegistered waits until the client IP of the test handshake is held by a
// writer on sess's adapter.
func waitRegistered(t *testing.T, st *SharedTUN, sess *HTTPPollingSession) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st.clientsMu.RLock()
		w := st.clients["10.99.0.9"]
		st.clientsMu.RUnlock()
		if w == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if pc, ok := w.conn.(*pollingTUNConn); ok && pc.sess == sess {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("polling session never registered")
}

// TestTakeoverOriginOnPollingAndH2 is P3-5 of the round-3 review of PR #126.
// The collision check compared conn.RemoteAddr(), and the Polling and H2
// adapters have none worth comparing: Polling says 127.0.0.1:0, H2 says nil. A
// Polling or H2 session taken over by the same client still logged the
// collision warning, and two Polling clients from different addresses did not.
// The sessions here go through the real handlers, so the origin they register
// with is the one the handler hands over.
func TestTakeoverOriginOnPollingAndH2(t *testing.T) {
	type step func(*testing.T, *serverContext, string)
	for _, tc := range []struct {
		name        string
		first, then step
		fromFirst   string
		fromThen    string
		warns       bool
	}{
		{"polling then h2, same client", pollingTakeover, h2Takeover, "192.0.2.170", "192.0.2.170", false},
		{"h2 then polling, same client", h2Takeover, pollingTakeover, "192.0.2.170", "192.0.2.170", false},
		{"polling then polling, other address", pollingTakeover, pollingTakeover, "192.0.2.170", "198.51.100.152", true},
		{"h2 then h2, other address", h2Takeover, h2Takeover, "192.0.2.170", "198.51.100.152", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &syncBuf{}
			log.SetOutput(out)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			srvCtx := newTestServerContext(t)
			srvCtx.cfg.TunIP = net.IPv4(10, 99, 0, 1).To4()
			srvCtx.sharedTUN = newTestSharedTUN(t)
			tc.first(t, srvCtx, tc.fromFirst)
			tc.then(t, srvCtx, tc.fromThen)

			if warned := strings.Contains(out.String(), "two clients may be sharing one tunnel IP"); warned != tc.warns {
				t.Fatalf("collision warning=%v, want %v; log:\n%s", warned, tc.warns, out)
			}
		})
	}
}

// TestUnknownOriginIsNotTheSameClient: two sessions whose origin nobody knows
// are not one client moving its tunnel. Before origins were passed in, two H2
// sessions (RemoteAddr nil) compared equal and a real collision went to Info.
func TestUnknownOriginIsNotTheSameClient(t *testing.T) {
	out := &syncBuf{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	st := newTestSharedTUN(t)
	ip := net.IPv4(10, 8, 0, 2)
	a, a2 := net.Pipe()
	b, b2 := net.Pipe()
	t.Cleanup(func() { a.Close(); a2.Close(); b.Close(); b2.Close() })
	st.RegisterClientGated(ip, "global", "", a, nil, nil, nil)
	st.RegisterClientGated(ip, "global", "", b, nil, nil, nil)
	if !strings.Contains(out.String(), "two clients may be sharing one tunnel IP") {
		t.Fatalf("a live takeover between two unknown origins was not flagged; log:\n%s", out)
	}
}
