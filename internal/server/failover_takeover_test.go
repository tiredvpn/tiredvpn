package server

import (
	"bytes"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
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
