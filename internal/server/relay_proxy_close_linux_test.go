package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A proxied target that hangs up: the exit's HTTP/2 Stego proxy read the
// target's end and told nobody. The client - or a relay, and the relay's
// client - waited for the rest of an answer that had ended, until the
// exit's 60 s read deadline closed the connection. Real clocks: the end has
// to arrive in well under that.

// byeTarget accepts one connection, sends "bye" and hangs up.
func byeTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("bye"))
		c.Close()
	}()
	return ln.Addr().String()
}

// readsByeThenEnd reads conn to its end within d and wants "bye".
func readsByeThenEnd(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read %q, then %v: the target's hang-up did not arrive within %v", got, err, d)
	}
	if string(got) != "bye" {
		t.Fatalf("read %q, want the target's bye", got)
	}
}

// TestAProxiedTargetsHangUpReachesTheClient: straight from the exit, over
// UpstreamDialer.Dial, the client the exit's proxy serves.
func TestAProxiedTargetsHangUpReachesTheClient(t *testing.T) {
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := NewUpstreamDialer(exit.addr, secret).Dial(ctx, byeTarget(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	readsByeThenEnd(t, conn, 5*time.Second)
}

// TestAProxiedTargetsHangUpReachesARelaysClient: through a relay's
// handleRawTunnel, which has to pass the end on to its own client.
func TestAProxiedTargetsHangUpReachesARelaysClient(t *testing.T) {
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close() })
	go handleRawTunnel(relaySide, relayCtx, testLogger(t), clientIdentity{})
	addr := []byte(byeTarget(t))
	if _, err := client.Write(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("relay ack %x: %v", ack, err)
	}
	readsByeThenEnd(t, client, 5*time.Second)
}
