package server

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestH2StegoHandshakeOverTLS exercises the full production path:
// a TLS connection with handleHTTP2WithALPN on the server (which performs
// the kTLS handover after reading the preface) against the real client
// handshake. This catches handshake hangs caused by the kTLS handover
// dropping decrypted SETTINGS/HEADERS bytes that were buffered in the TLS
// stack after the preface read.
func TestH2StegoHandshakeOverTLS(t *testing.T) {
	secret := []byte("test-stego-secret-32-bytes-long!")
	cert := selfSignedCertForTest(t)

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = secret
	logger := testLogger(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return
		}
		// handleHTTP2WithALPN performs readH2Preface then kTLS handover
		// then runH2FrameLoop — the exact production server path.
		handleHTTP2WithALPN(tlsConn, srvCtx, logger)
	}()

	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         "localhost",
	}
	clientTLS, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client tls.Dial: %v", err)
	}
	defer clientTLS.Close()

	stegoConn := strategy.NewHTTP2StegoConn(clientTLS, secret, true, strategy.NaivePaddingMinimal)

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
		t.Fatal("client handshake hung (timeout) over TLS — likely kTLS handover dropped buffered SETTINGS/HEADERS")
	}
}
