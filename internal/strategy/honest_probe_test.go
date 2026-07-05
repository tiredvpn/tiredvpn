package strategy

import (
	"context"
	"net"
	"testing"
	"time"
)

// closedTCPAddr returns an address that had a listener bound and then closed,
// so a TCP dial against it reliably yields "connection refused".
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// liveTCPAddr returns an address with an accepting listener; the returned
// closer must be called to release it.
func liveTCPAddr(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// prober is the shallow-probe surface shared by the three top strategies.
type prober interface {
	Probe(ctx context.Context, target string) error
}

func honestProbeCases(mgr *Manager) map[string]prober {
	secret := []byte("honest-probe-secret")
	return map[string]prober{
		"REALITY":         NewREALITYStrategy(mgr, secret),
		"WebSocketPadded": NewWebSocketPaddedStrategy(mgr, secret),
		"HTTPPolling":     NewHTTPPollingStrategy(mgr, secret),
	}
}

// Probe must fail when the server is unreachable, not return nil blindly.
func TestHonestProbe_UnreachableServer(t *testing.T) {
	for _, name := range []string{"REALITY", "WebSocketPadded", "HTTPPolling"} {
		t.Run(name, func(t *testing.T) {
			mgr := NewManager()
			mgr.serverAddrV4 = closedTCPAddr(t)
			p := honestProbeCases(mgr)[name]

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := p.Probe(ctx, "example.com:443"); err == nil {
				t.Fatalf("%s.Probe: expected error for unreachable server, got nil", name)
			}
		})
	}
}

// Probe must succeed against a reachable server, proving the check is a real
// TCP dial and not an unconditional failure.
func TestHonestProbe_ReachableServer(t *testing.T) {
	mgr := NewManager()
	addr, closer := liveTCPAddr(t)
	defer closer()
	mgr.serverAddrV4 = addr

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for name, p := range honestProbeCases(mgr) {
		t.Run(name, func(t *testing.T) {
			if err := p.Probe(ctx, "example.com:443"); err != nil {
				t.Fatalf("%s.Probe: expected nil for reachable server, got %v", name, err)
			}
		})
	}
}
