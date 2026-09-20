package strategy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// verifyServerKnock mirrors server.verifyFullKnockSequence for the v2 knock: it
// reads packet 0's fixed header, recovers the per-connection nonce and bucket,
// then recomputes the schedule, tag and every body byte from those and checks
// them. Returns true on a fully matching knock.
func verifyServerKnock(conn net.Conn, secret []byte, t *testing.T) bool {
	hdr := make([]byte, KnockHeaderLen)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Logf("knock header read error: %v", err)
		return false
	}
	if hdr[0] != 0x00 {
		t.Logf("knock packet 0: wrong seq number %d", hdr[0])
		return false
	}
	bucket := int64(binary.BigEndian.Uint64(hdr[1:9]))
	if !KnockBucketFresh(bucket) {
		t.Logf("knock bucket %d not fresh", bucket)
		return false
	}
	nonce := append([]byte(nil), hdr[9:KnockHeaderLen]...)
	seq := KnockScheduleFor(secret, nonce, bucket)

	rest0 := make([]byte, seq.Sizes[0]-KnockHeaderLen)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, rest0); err != nil {
		t.Logf("knock packet 0 body read error: %v", err)
		return false
	}
	if !bytes.Equal(rest0[:KnockTagLen], KnockTag(secret, nonce, bucket)) {
		t.Log("knock packet 0: tag mismatch")
		return false
	}
	if !bytes.Equal(rest0[KnockTagLen:], KnockBody(secret, nonce, bucket, 0, seq.Sizes[0]-KnockHeaderLen-KnockTagLen)) {
		t.Log("knock packet 0: body mismatch")
		return false
	}

	for i := 1; i < KnockPackets; i++ {
		buf := make([]byte, seq.Sizes[i])
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Logf("knock packet %d read error: %v", i, err)
			return false
		}
		if buf[0] != byte(i) {
			t.Logf("knock packet %d: wrong seq number got %d want %d", i, buf[0], i)
			return false
		}
		if !bytes.Equal(buf[1:], KnockBody(secret, nonce, bucket, i, seq.Sizes[i]-1)) {
			t.Logf("knock packet %d: body mismatch", i)
			return false
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
	setTestEndpoint(mgr, ln.Addr().String())
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
