package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/pool"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// scriptedExit is a pool.Connector whose exit side is a net.Pipe we drive from
// the test. It acks the target address (so DialTarget succeeds and the pool
// counts the slot) and then plays the scripted server behaviour.
type scriptedExit struct {
	strat  strategy.Strategy  // may be nil for the plain-HTTP path
	acked  chan struct{}      // closed once the ack has been written
	server func(srv net.Conn) // played after the ack
}

func (e *scriptedExit) Connect(_ context.Context, _ string) (net.Conn, strategy.Strategy, error) {
	cli, srv := net.Pipe()
	go func() {
		// Read the length-prefixed target DialTarget sends first.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(srv, lenBuf); err != nil {
			srv.Close()
			return
		}
		n := binary.BigEndian.Uint16(lenBuf)
		if _, err := io.ReadFull(srv, make([]byte, n)); err != nil {
			srv.Close()
			return
		}
		// Ack OK. After this the handler owns a counted pool slot.
		if _, err := srv.Write([]byte{0x00}); err != nil {
			srv.Close()
			return
		}
		close(e.acked)
		e.server(srv)
	}()
	return cli, e.strat, nil
}

// waitStat polls the pool count until it hits want or the budget runs out.
func waitStat(p *pool.TunnelPool, want int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if p.Stats() == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return p.Stats() == want
}

// TestPlainHTTPPooledReleasesSlotOnKeepAliveExit is the red-on-mutation test
// for the pool-counter leak. The exit sends a full response and then holds the
// connection open without EOF - a keep-alive upstream. The old handler relayed
// the response with an unbounded io.Copy and deadlines cleared to zero, so it
// blocked here forever and its serverConn.Close() (the only place the pool
// slot is released) was never reached. Pre-fix: Stats() stays pinned at 1.
// Post-fix: the idle-bounded copy returns and the deferred Close releases it.
func TestPlainHTTPPooledReleasesSlotOnKeepAliveExit(t *testing.T) {
	old := plainHTTPResponseIdle
	plainHTTPResponseIdle = 100 * time.Millisecond
	defer func() { plainHTTPResponseIdle = old }()

	exit := &scriptedExit{acked: make(chan struct{})}
	exit.server = func(srv net.Conn) {
		// Fully drain the forwarded request (up to the blank line) so the
		// handler's Write completes, then reply and act like a keep-alive
		// upstream: never send EOF, just hold the socket until the handler
		// closes it (which only happens once the leak is fixed).
		br := bufio.NewReader(srv)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				srv.Close()
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		srv.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
		io.Copy(io.Discard, br) // blocks until the handler closes the conn
		srv.Close()
	}

	p := pool.NewTunnelPoolFromConnector(exit, pool.DefaultConfig())

	clientSrv, clientCli := net.Pipe()
	go handleHTTPProxyPooled(clientSrv, p, 1)
	go io.Copy(io.Discard, clientCli) // drain the handler's response writes
	go clientCli.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	select {
	case <-exit.acked:
	case <-time.After(3 * time.Second):
		t.Fatal("exit never acked: handler did not acquire a pooled connection")
	}

	if !waitStat(p, 0, 2*time.Second) {
		t.Fatalf("plain-HTTP handler leaked the pool slot: Stats()=%d after relay, want 0", p.Stats())
	}
	clientCli.Close()
}

// fakeExitStrategy satisfies strategy.Strategy for the CONNECT/SOCKS paths,
// which read Strategy().ID()/Name() on the pooled conn.
type fakeExitStrategy struct{}

func (fakeExitStrategy) Name() string                        { return "fake" }
func (fakeExitStrategy) ID() string                          { return "fake" }
func (fakeExitStrategy) Priority() int                       { return 1 }
func (fakeExitStrategy) Probe(context.Context, string) error { return nil }
func (fakeExitStrategy) Connect(context.Context, string) (net.Conn, error) {
	return nil, nil
}
func (fakeExitStrategy) RequiresServer() bool { return true }
func (fakeExitStrategy) Description() string  { return "fake exit" }

// TestConnectPooledReleasesSlotOnClientHangup guards the CONNECT path: when the
// browser hangs up, PooledRelay returns and the deferred Close must release the
// pool slot. (This path already released pre-fix; the test pins the behaviour
// so the defer conversion cannot regress it.)
func TestConnectPooledReleasesSlotOnClientHangup(t *testing.T) {
	exit := &scriptedExit{strat: fakeExitStrategy{}, acked: make(chan struct{})}
	exit.server = func(srv net.Conn) {
		io.Copy(io.Discard, srv) // relay quietly until the handler tears down
		srv.Close()
	}

	p := pool.NewTunnelPoolFromConnector(exit, pool.DefaultConfig())

	clientSrv, clientCli := net.Pipe()
	go handleHTTPProxyPooled(clientSrv, p, 1)
	go io.Copy(io.Discard, clientCli)
	go clientCli.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"))

	select {
	case <-exit.acked:
	case <-time.After(3 * time.Second):
		t.Fatal("exit never acked: handler did not acquire a pooled connection")
	}

	// Browser hangs up -> relay ends -> deferred Close releases the slot.
	clientCli.Close()
	if !waitStat(p, 0, 2*time.Second) {
		t.Fatalf("CONNECT handler leaked the pool slot: Stats()=%d after hangup, want 0", p.Stats())
	}
}
