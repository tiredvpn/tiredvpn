package strategy

import (
	"net"
	"testing"
)

// F1 (S22): the auth token of every InsecureSkipVerify strategy must be bound
// to the TLS session exporter, so a token captured on one session is worthless
// on another. Each test here mints a token on one exporter and asserts it fails
// on a different one. Predelivered to the pre-binding code (drop the h.Write(ekm)
// in the matching derivation) each of these goes green-to-red, which is what
// makes the binding, not just the token, the thing under test.

// stegoHandshakeOverTCP runs the HTTP/2 stego client and server roles over a
// loopback TCP pair (buffered, unlike net.Pipe, so the interleaved
// SETTINGS/HEADERS writes don't deadlock). The client uses clientEKM, the
// server serverEKM; it returns the client and server handshake errors.
func stegoHandshakeOverTCP(t *testing.T, secret, clientEKM, serverEKM []byte) (clientErr, serverErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer raw.Close()
		s := NewHTTP2StegoConn(raw, secret, false, NaivePaddingMinimal, serverEKM)
		srvErrCh <- s.Handshake()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := NewHTTP2StegoConn(raw, secret, true, NaivePaddingMinimal, clientEKM)
	clientErr = c.Handshake()
	serverErr = <-srvErrCh
	return clientErr, serverErr
}

// TestStegoHandshakeRejectsCrossSessionToken gives the client and server
// different session exporters; the client's token is bound to one and the
// server verifies against the other, so the handshake must fail. The positive
// control (same exporter) is TestStegoHandshakeSameSessionToken.
func TestStegoHandshakeRejectsCrossSessionToken(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-xsession-secret")
	ekmA := []byte("exporter-A-0123456789abcdef012345")
	ekmB := []byte("exporter-B-0123456789abcdef012345")

	clientErr, serverErr := stegoHandshakeOverTCP(t, secret, ekmA, ekmB)
	if serverErr == nil {
		t.Fatal("server accepted a token bound to a different session; not session-bound")
	}
	if clientErr == nil {
		t.Fatal("client handshake succeeded with a token bound to a different session; not session-bound")
	}
}

// TestStegoHandshakeSameSessionToken is the positive control: identical
// exporters on both ends complete the handshake. Without it a stego conn that
// simply always failed would pass the cross-session test above.
func TestStegoHandshakeSameSessionToken(t *testing.T) {
	t.Parallel()
	secret := []byte("stego-samesession-secret")
	ekm := []byte("exporter-shared-0123456789abcdef0")

	clientErr, serverErr := stegoHandshakeOverTCP(t, secret, ekm, ekm)
	if clientErr != nil {
		t.Fatalf("client handshake failed on a shared session exporter: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake failed on a shared session exporter: %v", serverErr)
	}
}
