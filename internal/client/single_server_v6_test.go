package client

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/pool"
)

// TestBuildManager_SingleServerBareV6 drives the path Run and the Android
// entry point take - buildManager over a Config carrying only -server and a
// raw -server-v6 - and reads the candidates the manager's selector will dial.
func TestBuildManager_SingleServerBareV6(t *testing.T) {
	for _, v6 := range []string{"2001:db8::2", "[2001:db8::2]"} {
		cfg := &Config{
			ServerAddr:   "203.0.113.10:995",
			ServerAddrV6: v6,
			PreferIPv6:   true,
			FallbackToV4: true,
		}
		mgr, err := buildManager(cfg, "secret")
		if err != nil {
			t.Fatalf("-server-v6 %q: buildManager: %v", v6, err)
		}
		states := mgr.EndpointStates()
		if len(states) != 2 || states[0].Addr != "[2001:db8::2]:995" || states[1].Addr != "203.0.113.10:995" {
			t.Fatalf("-server-v6 %q: candidates = %+v, want [2001:db8::2]:995 then 203.0.113.10:995", v6, states)
		}
	}
}

// recordingDialer stands in for the tunnel pool: it records the target a
// local proxy request was turned into and refuses it, so the handler answers
// with its failure reply and returns.
type recordingDialer struct {
	mu      sync.Mutex
	targets []string
}

func (d *recordingDialer) DialTarget(_ context.Context, target string) (*pool.PooledConn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.mu.Unlock()
	return nil, errors.New("test: refused")
}

func (d *recordingDialer) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// runProxy feeds req to handle over an in-memory connection and drains the
// reply, returning once the handler has finished.
func runProxy(t *testing.T, handle func(net.Conn), req []byte) {
	t.Helper()
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(srv)
	}()
	go func() {
		_, _ = cli.Write(req)
	}()
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, bufio.NewReader(cli))
	cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
}

// TestLocalProxyTargets_IPv6 checks the target string each local proxy
// front-end hands the tunnel for an IPv6 destination. Each case enters through
// the real handler, so the assertion is on the call site, not on a helper.
func TestLocalProxyTargets_IPv6(t *testing.T) {
	cases := []struct {
		name string
		req  []byte
		via  string // "http" or "socks"
		want string
	}{
		{"CONNECT [v6] without port", []byte("CONNECT [2001:db8::1] HTTP/1.1\r\n\r\n"), "http", "[2001:db8::1]:443"},
		{"CONNECT [v6]:port", []byte("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"), "http", "[2001:db8::1]:8443"},
		{"CONNECT host without port", []byte("CONNECT vpn.example.org HTTP/1.1\r\n\r\n"), "http", "vpn.example.org:443"},
		{"GET http://[v6]/", []byte("GET http://[2001:db8::1]/x HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n"), "http", "[2001:db8::1]:80"},
		{"GET https://[v6]/", []byte("GET https://[2001:db8::1]/x HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n"), "http", "[2001:db8::1]:443"},
		{"GET http://[v6]:port/", []byte("GET http://[2001:db8::1]:8080/x HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n"), "http", "[2001:db8::1]:8080"},
		{"SOCKS5 domain carrying a v6 literal", socks5DomainRequest("2001:db8::1", 443), "socks", "[2001:db8::1]:443"},
		{"SOCKS5 domain", socks5DomainRequest("vpn.example.org", 443), "socks", "vpn.example.org:443"},
		{"SOCKS5 IPv4", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x01, 0xbb}, "socks", "203.0.113.7:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDialer{}
			handle := func(c net.Conn) { handleHTTPProxyPooled(c, d, 1) }
			if tc.via == "socks" {
				handle = func(c net.Conn) { handleSOCKS5Pooled(c, d, 1) }
			}
			runProxy(t, handle, tc.req)
			if got := d.got(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("tunnel targets = %q, want [%q]", got, tc.want)
			}
		})
	}
}

// socks5DomainRequest is a no-auth greeting followed by a CONNECT to a domain.
func socks5DomainRequest(domain string, port int) []byte {
	b := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	b = append(b, domain...)
	return append(b, byte(port>>8), byte(port))
}
