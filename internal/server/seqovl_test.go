package server

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// makeTestDecoy builds a seqovl decoy record the same way the client does, using
// the production seqovlMarker so the test exercises the real wire contract.
func makeTestDecoy(t *testing.T, secret []byte, junkLen int) []byte {
	t.Helper()
	nonce := make([]byte, seqovlNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if nonce[0] == 0x01 {
		nonce[0] = 0x02
	}
	marker := seqovlMarker(secret, nonce)
	junk := make([]byte, junkLen)
	_, _ = rand.Read(junk)

	payloadLen := seqovlNonceLen + seqovlMarkerLen + junkLen
	rec := make([]byte, 5+payloadLen)
	rec[0] = recordTypeHandshake
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(payloadLen >> 8)
	rec[4] = byte(payloadLen)
	copy(rec[5:], nonce)
	copy(rec[5+seqovlNonceLen:], marker)
	copy(rec[5+seqovlNonceLen+seqovlMarkerLen:], junk)
	return rec
}

func TestIsSeqovlDecoyGlobalSecret(t *testing.T) {
	secret := []byte("global-secret")
	srvCtx := &serverContext{cfg: &Config{Secret: secret}}

	decoy := makeTestDecoy(t, secret, 64)
	if !isSeqovlDecoy(decoy, srvCtx) {
		t.Fatal("valid decoy under global secret not recognised")
	}
}

func TestIsSeqovlDecoyRejectsRealClientHello(t *testing.T) {
	secret := []byte("global-secret")
	srvCtx := &serverContext{cfg: &Config{Secret: secret}}

	// A minimal record whose handshake body begins with 0x01 (ClientHello).
	ch := make([]byte, 5+seqovlMinDecoyPayload)
	ch[0] = recordTypeHandshake
	ch[3] = byte(seqovlMinDecoyPayload >> 8)
	ch[4] = byte(seqovlMinDecoyPayload)
	ch[5] = handshakeTypeClientHello // payload[0] == 0x01
	if isSeqovlDecoy(ch, srvCtx) {
		t.Fatal("real ClientHello falsely detected as seqovl decoy")
	}
}

func TestIsSeqovlDecoyRejectsWrongSecret(t *testing.T) {
	srvCtx := &serverContext{cfg: &Config{Secret: []byte("server-secret")}}

	decoy := makeTestDecoy(t, []byte("other-secret"), 64)
	if isSeqovlDecoy(decoy, srvCtx) {
		t.Fatal("decoy built with a foreign secret must not be accepted")
	}
}

func TestIsSeqovlDecoyRejectsRandomTraffic(t *testing.T) {
	srvCtx := &serverContext{cfg: &Config{Secret: []byte("server-secret")}}

	junk := make([]byte, 5+128)
	_, _ = rand.Read(junk)
	junk[0] = recordTypeHandshake
	junk[3] = byte(128 >> 8)
	junk[4] = byte(128)
	// Ensure the (random) handshake-body first byte is not 0x01 so we actually
	// exercise the HMAC path rather than the fast gate.
	if junk[5] == handshakeTypeClientHello {
		junk[5] = 0x02
	}
	if isSeqovlDecoy(junk, srvCtx) {
		t.Fatal("random handshake-looking traffic accepted as decoy")
	}
}

func TestIsSeqovlDecoyNilRegistrySafe(t *testing.T) {
	srvCtx := &serverContext{cfg: &Config{Secret: nil}, registry: nil}
	decoy := makeTestDecoy(t, []byte("x"), 32)
	// No global secret, no registry: nothing to match, must not panic.
	if isSeqovlDecoy(decoy, srvCtx) {
		t.Fatal("decoy accepted with no known secrets")
	}
}

// TestReadFirstPeekSkipsDecoy exercises the exact readFirstPeek + decoy-skip
// loop used in handleConnection: a decoy followed by the real first flight must
// yield the real record.
func TestReadFirstPeekSkipsDecoy(t *testing.T) {
	secret := []byte("global-secret")
	srvCtx := &serverContext{cfg: &Config{Secret: secret}}
	logger := log.WithPrefix("test")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	decoy := makeTestDecoy(t, secret, 80)

	// A real REALITY-less ClientHello record (payload[0] == 0x01) is enough here:
	// the loop only needs isSeqovlDecoy to return false for it.
	realCH := make([]byte, 5+seqovlMinDecoyPayload)
	realCH[0] = recordTypeHandshake
	realCH[1] = 0x03
	realCH[2] = 0x03
	realCH[3] = byte(seqovlMinDecoyPayload >> 8)
	realCH[4] = byte(seqovlMinDecoyPayload)
	realCH[5] = handshakeTypeClientHello
	for i := 6; i < len(realCH); i++ {
		realCH[i] = byte(i)
	}

	go func() {
		_, _ = client.Write(decoy)
		_, _ = client.Write(realCH)
	}()

	header, peekBuf, ok := readFirstPeek(server, logger)
	if !ok {
		t.Fatal("readFirstPeek failed on decoy record")
	}
	decoyCount := 0
	for header[0] == 0x16 && isSeqovlDecoy(peekBuf, srvCtx) {
		decoyCount++
		if decoyCount > seqovlMaxDecoys {
			t.Fatal("decoy limit exceeded unexpectedly")
		}
		header, peekBuf, ok = readFirstPeek(server, logger)
		if !ok {
			t.Fatal("readFirstPeek failed reading real first flight")
		}
	}

	if decoyCount != 1 {
		t.Fatalf("expected to skip exactly 1 decoy, skipped %d", decoyCount)
	}
	if !bytes.Equal(peekBuf, realCH) {
		t.Fatalf("real first flight corrupted after decoy skip")
	}
}

// TestReadFirstPeekNoDecoyUnchanged verifies a plain ClientHello (no decoy) is
// returned as-is with no skipping — the baseline path must be untouched.
func TestReadFirstPeekNoDecoyUnchanged(t *testing.T) {
	logger := log.WithPrefix("test")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	realCH := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x02}

	go func() {
		_, _ = client.Write(realCH)
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	header, peekBuf, ok := readFirstPeek(server, logger)
	if !ok {
		t.Fatal("readFirstPeek failed on plain ClientHello")
	}
	if header[0] != 0x16 {
		t.Fatalf("header type = 0x%02x", header[0])
	}
	if !bytes.Equal(peekBuf, realCH) {
		t.Fatalf("plain ClientHello altered: got %x want %x", peekBuf, realCH)
	}
}
