package server

import (
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"golang.org/x/net/http2/hpack"
)

// TestH2StegoHandshakeEndToEnd drives the real client handshake
// (strategy.HTTP2StegoConn.Handshake) against the real server frame loop
// (readH2Preface -> newH2Framer -> runH2FrameLoop) over a loopback TCP
// connection (buffered, like production; net.Pipe would deadlock on the
// server SETTINGS write because it is unbuffered).
//
// It reproduces the "TCP up, handshake hangs to timeout" symptom: the client
// blocks in waitForServerAck because the server never emits the auth ack the
// client expects.
func TestH2StegoHandshakeEndToEnd(t *testing.T) {
	secret := []byte("test-stego-secret-32-bytes-long!")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = secret
	logger := testLogger(t)

	serverErr := make(chan error, 1)
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer serverConn.Close()

		if err := readH2Preface(serverConn, logger); err != nil {
			serverErr <- err
			return
		}
		framer, err := newH2Framer(serverConn, logger)
		if err != nil {
			serverErr <- err
			return
		}
		hpackDec := hpack.NewDecoder(4096, nil)
		authenticated := false
		var authClientID clientIdentity
		var tunnel *h2TunnelState
		var connTracked bool
		serverErr <- nil
		runH2FrameLoop(&serverConn, &framer, hpackDec, srvCtx, logger, &authenticated, &authClientID, &connTracked, &tunnel, nil)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	stegoConn := strategy.NewHTTP2StegoConn(clientConn, secret, true, strategy.NaivePaddingMinimal)

	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- stegoConn.Handshake()
	}()

	select {
	case err := <-handshakeDone:
		if err != nil {
			t.Fatalf("client handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client handshake hung (timeout) — server never sent auth ack")
	}
}
