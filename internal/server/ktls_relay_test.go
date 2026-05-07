package server

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestRawTunnelKTLSHandover verifies that handleRawTunnel correctly relays
// data through the kTLS handover boundary. After the success ack, the
// handler swaps the underlying conn from *tls.Conn to *ktls.Conn (Linux
// with kTLS support) or leaves it as *tls.Conn (other platforms /
// no kTLS support). In either case, bytes must round-trip intact between
// the client and the in-process echo target via the relay goroutines.
//
// Regression: if a future change reintroduces a TLS-stack read after
// TryEnable on a kTLS-active socket, the test will hang or read garbage
// instead of silently losing bytes in production.
func TestRawTunnelKTLSHandover(t *testing.T) {
	cert := selfSignedCertForTest(t)
	srvCtx := newTestServerContext(t)
	logger := testLogger(t)

	// In-process echo target — handleRawTunnel will dial this address.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	// TLS listener with tired-raw ALPN.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"tired-raw"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Server goroutine: accept one TLS conn, run handleRawTunnel.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			return
		}
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return
		}
		handleRawTunnel(tlsConn, srvCtx, logger, "")
	}()

	// Client: dial, complete TLS handshake, send tired-raw frame.
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"tired-raw"},
		ServerName:         "localhost",
	}
	clientTLS, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client tls.Dial: %v", err)
	}
	defer clientTLS.Close()

	clientTLS.SetDeadline(time.Now().Add(5 * time.Second))

	addr := target.Addr().String()
	frame := []byte{byte(len(addr) >> 8), byte(len(addr))}
	frame = append(frame, []byte(addr)...)
	if _, err := clientTLS.Write(frame); err != nil {
		t.Fatalf("client write addr frame: %v", err)
	}

	// Read 1-byte success ack — this is the last byte the server writes
	// through the TLS stack before kTLS handover.
	ack := make([]byte, 1)
	if _, err := io.ReadFull(clientTLS, ack); err != nil {
		t.Fatalf("client read ack: %v", err)
	}
	if ack[0] != 0x00 {
		t.Fatalf("ack=0x%02x, want 0x00", ack[0])
	}

	// Send a payload, expect the in-process echo target to bounce it back.
	// On Linux + kTLS, this round-trip exercises the kernel-offloaded path
	// in both directions. On other platforms, it exercises the same path
	// the production server would use without kTLS.
	payload := []byte("hello kTLS relay phase")
	if _, err := clientTLS.Write(payload); err != nil {
		t.Fatalf("client write payload: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientTLS, got); err != nil {
		t.Fatalf("client read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}

	// Close the client to signal end-of-stream to the server's relay
	// goroutines, then wait for the handler to return.
	clientTLS.Close()

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("server did not finish within 5 seconds after client close")
	}
}
