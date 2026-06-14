package strategy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// verifyServerKnock mirrors server.verifyFullKnockSequence: it reads the 5
// timing-knock packets the client sends and validates sequence numbers and
// HMAC-derived content. Returns true on a fully matching knock.
func verifyServerKnock(conn net.Conn, secret []byte, t *testing.T) bool {
	seqHash := hmac.New(sha256.New, secret)
	seqHash.Write([]byte("knock-sequence"))
	seqHashSum := seqHash.Sum(nil)

	sizes := make([]int, 5)
	for i := 0; i < 5; i++ {
		sizes[i] = 10 + int(seqHashSum[i+5])%90
	}

	for i := 0; i < 5; i++ {
		buf := make([]byte, sizes[i])
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Logf("knock packet %d read error: %v", i, err)
			return false
		}
		if buf[0] != byte(i) {
			t.Logf("knock packet %d: wrong seq number got %d want %d", i, buf[0], i)
			return false
		}
		h := hmac.New(sha256.New, secret)
		h.Write([]byte{byte(i)})
		expected := h.Sum(nil)
		for j := 1; j < len(buf); j++ {
			if buf[j] != expected[(j-1)%len(expected)] {
				t.Logf("knock packet %d: content mismatch at byte %d", i, j)
				return false
			}
		}
	}
	conn.SetReadDeadline(time.Time{})
	return true
}

// TestAntiProbeEndToEndHandshake exercises the real client Connect knock against
// a server that follows the production dispatch path: TLS handshake, then read
// the 1-byte protocol discriminator (protocol.ReadDispatch), then verify the
// knock. This reproduces the auth hang reported when the client omits the
// dispatch byte.
func TestAntiProbeEndToEndHandshake(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	secret := []byte("antiprobe-e2e-secret")

	serverResult := make(chan bool, 1)
	go func() {
		tlsLn := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		})
		conn, err := tlsLn.Accept()
		if err != nil {
			serverResult <- false
			return
		}
		defer conn.Close()

		// Production server path: handleTLSConnection reads a dispatch byte first.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		protoType, err := protocol.ReadDispatch(conn)
		if err != nil {
			t.Logf("server: ReadDispatch failed: %v", err)
			serverResult <- false
			return
		}
		conn.SetReadDeadline(time.Time{})

		if protoType != protocol.TypeAntiProbe {
			t.Logf("server: unexpected dispatch type 0x%02x", protoType)
			serverResult <- false
			return
		}

		if !verifyServerKnock(conn, secret, t) {
			serverResult <- false
			return
		}
		// Send ACK the client waits for in timingKnock.
		conn.Write([]byte{0x01})
		serverResult <- true
	}()

	mgr := NewManager()
	mgr.serverAddrV4 = ln.Addr().String()
	strat := NewAntiProbeStrategy(mgr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := strat.Connect(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	defer conn.Close()

	select {
	case ok := <-serverResult:
		if !ok {
			t.Fatal("server did not authenticate the anti-probe knock")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("handshake hung: server never completed authentication")
	}
}
