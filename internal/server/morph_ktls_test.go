package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestMorphKTLSHandover stands up a TLS listener with tired-morph ALPN,
// runs handleMorphConnection in-process for one accepted connection, and
// drives the early-ack handshake + target exchange + payload round-trip
// against an in-process echo target. Asserts:
//  1. Server writes a 1-byte ack (0x00) after auth succeeds.
//  2. After kTLS handover, the morph-framed target packet round-trips
//     and the dial-status response is morph-framed (7 bytes).
//  3. A subsequent payload from the client echoes back through the
//     relay and the morph framing.
//
// On Linux + kTLS-capable kernel this exercises the kernel offload path.
// On other platforms TryEnable is a no-op and the test exercises the
// (identical) byte path through the *tls.Conn.
//
// This test mirrors TestRawTunnelKTLSHandover from Phase 1, with the
// additional early-ack step that defines the kTLS handover boundary
// for tired-morph.
func TestMorphKTLSHandover(t *testing.T) {
	cert := selfSignedCertForTest(t)
	srvCtx := newTestServerContext(t)
	logger := testLogger(t)

	// Configure a global secret so the morph auth check passes via the
	// global-secret fallback (no registry needed).
	srvCtx.cfg.Secret = []byte("test-morph-secret-32-bytes-long-x")

	// In-process echo target.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	// echoConn is captured so we can close it explicitly after the test
	// payload round-trip, unblocking the server's target→client relay goroutine.
	echoConnCh := make(chan net.Conn, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		echoConnCh <- c
		io.Copy(c, c)
		c.Close()
	}()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"tired-morph"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

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
		handleMorphConnection(tlsConn, srvCtx, logger)
	}()

	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"tired-morph"},
		ServerName:         "localhost",
	}
	clientTLS, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client tls.Dial: %v", err)
	}
	defer clientTLS.Close()
	clientTLS.SetDeadline(time.Now().Add(5 * time.Second))

	// Build morph handshake: MRPH(4) + nameLen(1) + name + auth(32).
	// Profile name "test" — the server doesn't check the name, only auth.
	profileName := []byte("test")
	authToken := computeMorphAuthForTest(t, srvCtx.cfg.Secret)
	hs := []byte("MRPH")
	hs = append(hs, byte(len(profileName)))
	hs = append(hs, profileName...)
	hs = append(hs, authToken...)

	if _, err := clientTLS.Write(hs); err != nil {
		t.Fatalf("client write handshake: %v", err)
	}

	// Read 1-byte early ack — this is the byte the server writes
	// immediately after auth success, defining the kTLS handover boundary.
	ack := make([]byte, 1)
	if _, err := io.ReadFull(clientTLS, ack); err != nil {
		t.Fatalf("client read early-ack: %v", err)
	}
	if ack[0] != 0x00 {
		t.Fatalf("early-ack=0x%02x, want 0x00", ack[0])
	}

	// Build morph first packet with target address.
	// Wire format: [dataLen:4 BE][padLen:2 BE][data:N] where
	// data = [addrLen:2 BE][addr:N], so dataLen = 2 + len(addr).
	// padLen = 0 for tests.
	addr := target.Addr().String()
	addrBytes := []byte(addr)
	dataLen := 2 + len(addrBytes)
	frame := make([]byte, 6+dataLen)
	frame[0] = byte(dataLen >> 24)
	frame[1] = byte(dataLen >> 16)
	frame[2] = byte(dataLen >> 8)
	frame[3] = byte(dataLen)
	frame[4] = 0 // padLen high
	frame[5] = 0 // padLen low
	frame[6] = byte(len(addrBytes) >> 8)
	frame[7] = byte(len(addrBytes))
	copy(frame[8:], addrBytes)

	if _, err := clientTLS.Write(frame); err != nil {
		t.Fatalf("client write target frame: %v", err)
	}

	// Read the 7-byte morph-framed dial-status response.
	// Server sends: {0x00,0x00,0x00,0x01,0x00,0x00,0x00} on success.
	// Format: [dataLen=1:4 BE][padLen=0:2 BE][status:1].
	status := make([]byte, 7)
	if _, err := io.ReadFull(clientTLS, status); err != nil {
		t.Fatalf("client read dial-status: %v", err)
	}
	if status[0] != 0 || status[1] != 0 || status[2] != 0 || status[3] != 1 {
		t.Fatalf("dial-status dataLen header=% x, want 00 00 00 01", status[:4])
	}
	if status[4] != 0 || status[5] != 0 {
		t.Fatalf("dial-status padLen=% x, want 00 00", status[4:6])
	}
	if status[6] != 0x00 {
		t.Fatalf("dial-status byte=0x%02x, want 0x00 (success)", status[6])
	}

	// Send a payload through morph framing: [dataLen=N:4][padLen=0:2][data:N].
	payload := []byte("morph kTLS round-trip payload")
	pl := len(payload)
	plFrame := make([]byte, 6+pl)
	plFrame[0] = byte(pl >> 24)
	plFrame[1] = byte(pl >> 16)
	plFrame[2] = byte(pl >> 8)
	plFrame[3] = byte(pl)
	plFrame[4] = 0
	plFrame[5] = 0
	copy(plFrame[6:], payload)

	if _, err := clientTLS.Write(plFrame); err != nil {
		t.Fatalf("client write payload: %v", err)
	}

	// Read echo: morph-framed [dataLen:4][padLen:2][data:N][padding:M].
	// The server relay wraps target→client data with padLen=30 (fixed).
	echoHdr := make([]byte, 6)
	if _, err := io.ReadFull(clientTLS, echoHdr); err != nil {
		t.Fatalf("client read echo header: %v", err)
	}
	echoLen := int(echoHdr[0])<<24 | int(echoHdr[1])<<16 | int(echoHdr[2])<<8 | int(echoHdr[3])
	echoPad := int(echoHdr[4])<<8 | int(echoHdr[5])
	if echoLen != pl {
		t.Fatalf("echo dataLen=%d, want %d", echoLen, pl)
	}
	echoData := make([]byte, echoLen)
	if _, err := io.ReadFull(clientTLS, echoData); err != nil {
		t.Fatalf("client read echo data: %v", err)
	}
	if string(echoData) != string(payload) {
		t.Fatalf("echo data=%q, want %q", echoData, payload)
	}
	// Discard padding (server relay uses fixed padLen=30).
	if echoPad > 0 {
		discard := make([]byte, echoPad)
		if _, err := io.ReadFull(clientTLS, discard); err != nil {
			t.Fatalf("client read echo padding: %v", err)
		}
	}

	// Close the client connection. This causes the server's client→target
	// relay goroutine to exit (reads EOF). Then close the echo target
	// connection to unblock the server's target→client relay goroutine
	// (which is blocked on targetConn.Read). Both relay goroutines must
	// exit before handleMorphConnection returns.
	clientTLS.Close()
	select {
	case echoConn := <-echoConnCh:
		echoConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatalf("echo conn never appeared")
	}
	target.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("server did not finish within 5s after client close")
	}
}

// computeMorphAuthForTest replicates the production auth-token computation.
//
// Option B: the production helper generateAuthToken lives in
// internal/strategy/stego.go (package strategy) and is package-private — it
// cannot be imported from package server. This function inlines the identical
// HMAC-SHA256 logic verbatim. If the auth scheme changes, update both this
// function and internal/strategy/stego.go:generateAuthToken in lock-step.
//
// Production source: internal/strategy/stego.go:generateAuthToken
// Wire-protocol verifier: internal/server/server.go:verifyMorphAuth
func computeMorphAuthForTest(t *testing.T, secret []byte) []byte {
	t.Helper()

	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60))

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	return h.Sum(nil)[:32]
}
