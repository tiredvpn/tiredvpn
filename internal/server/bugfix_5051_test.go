package server

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestHandleHTTP1_FakeSiteReplaysConsumedRequest guards issue #50.1: handleHTTP1
// drains the client's request via conn.Read before falling through to the fake
// nginx site. serveFakeWebsite starts a fresh http.ReadRequest, so unless those
// consumed bytes are replayed it blocks on an empty socket until the 75s
// keep-alive timeout and the client gets 0 bytes. This test sends one complete
// request and requires a prompt nginx 200; the pre-fix code hangs and trips the
// read deadline.
func TestHandleHTTP1_FakeSiteReplaysConsumedRequest(t *testing.T) {
	srvCtx := newTestServerContext(t)
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		handleHTTP1(server, srvCtx, testLogger(t))
		server.Close()
		close(done)
	}()

	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Without the replay fix these reads block until the 75s keep-alive timeout.
	// Drain the full response so the server's synchronous body write (net.Pipe)
	// completes and the handler can return on Connection: close.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := client.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
		if strings.Contains(sb.String(), "</html>") {
			break
		}
	}
	resp := sb.String()
	if resp == "" {
		t.Fatal("no fake response (regression: handler hung on empty socket?)")
	}
	if !strings.Contains(resp, "HTTP/1.1 200") {
		t.Fatalf("expected nginx 200, got: %.80q", resp)
	}
	if !strings.Contains(resp, "nginx") {
		t.Fatalf("expected nginx Server header, got: %.80q", resp)
	}

	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTP1 did not return after Connection: close")
	}
}

// TestTunModeReady guards issue #51: an exit started without -ip-pool has no
// shared TUN and rejects every native full-tunnel client ("Shared TUN not
// initialized"). tunModeReady surfaces that at boot. The bug is not
// IPv6/auto-IP specific — it is purely about whether the shared TUN exists.
func TestTunModeReady(t *testing.T) {
	if ok, reason := tunModeReady(nil); ok || reason == "" {
		t.Fatalf("nil srvCtx: got ok=%v reason=%q, want not-ready with reason", ok, reason)
	}

	// Exit without -ip-pool: no shared TUN, no upstream -> not ready.
	if ok, reason := tunModeReady(&serverContext{}); ok || reason == "" {
		t.Fatalf("no sharedTUN/no upstream: got ok=%v reason=%q, want not-ready with reason", ok, reason)
	}

	// Relay: upstream set -> ready even without a local shared TUN.
	if ok, _ := tunModeReady(&serverContext{upstreamDialer: &UpstreamDialer{}}); !ok {
		t.Fatal("relay (upstreamDialer set) should be TUN-ready")
	}

	// Exit with shared TUN configured -> ready.
	if ok, _ := tunModeReady(&serverContext{sharedTUN: &SharedTUN{}}); !ok {
		t.Fatal("exit with sharedTUN should be TUN-ready")
	}
}
