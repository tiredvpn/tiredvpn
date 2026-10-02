package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestReconnectHandshakeCancel: the reconnect handshake waits up to its read
// timeout for the exit's answer. Cancelling the reconnect (the control server
// closing) has to end that wait at once and close the connection.
func TestReconnectHandshakeCancel(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	gotReq := make(chan struct{})
	srvGone := make(chan struct{})
	go func() {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(srv, buf); err == nil {
			close(gotReq)
		}
		for {
			if _, err := srv.Read(buf); err != nil {
				close(srvGone)
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, _, _, _, err := reconnectHandshake(ctx, cli, net.IPv4(10, 9, 0, 2), 1280, false)
		errCh <- err
	}()
	select {
	case <-gotReq:
	case <-time.After(3 * time.Second):
		t.Fatal("positive control: the handshake request was never sent")
	}

	begin := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a cancelled handshake reported success")
		}
		if d := time.Since(begin); d > time.Second {
			t.Errorf("handshake took %v to notice the cancel", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the cancelled handshake kept waiting for the exit")
	}
	select {
	case <-srvGone:
	case <-time.After(2 * time.Second):
		t.Error("the cancelled handshake left the connection open")
	}
}
