package tun

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestAnAndroidConnectRefusalCountsAsAnAnswer is P3-4 on the Android
// core's first connect: a refusal there did not end the server's run of
// unanswered handshakes either.
func TestAnAndroidConnectRefusalCountsAsAnAnswer(t *testing.T) {
	var mu sync.Mutex
	var outcomes []bool
	h := newCtlHarnessWith(t, &ControlConfig{MTU: 1280, HandshakeOutcomeFn: func(answered bool, err error) error {
		mu.Lock()
		outcomes = append(outcomes, answered)
		mu.Unlock()
		return err
	}})
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		req := make([]byte, 8)
		if _, err := io.ReadFull(srv, req); err != nil {
			return
		}
		_, _ = srv.Write([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	}()
	h.cs.mu.Lock()
	h.cs.serverConn = nil
	h.cs.assignedIP = nil
	h.cs.serverIP = nil
	h.cs.waitingForFd = false
	h.cs.config.ConnectFn = func(context.Context) (net.IP, net.IP, net.Conn, error) {
		return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), cli, nil
	}
	h.cs.mu.Unlock()

	select {
	case resp := <-h.sendAsync(`{"command":"connect"}`+"\n", -1):
		if resp.Status != "error" {
			t.Fatalf("a refused connect answered %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connect never answered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 1 || !outcomes[0] {
		t.Fatalf("handshake outcomes %v, want one answered", outcomes)
	}
}
