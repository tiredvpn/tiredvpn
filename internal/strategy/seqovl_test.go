package strategy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

// recomputeMarker mirrors the server-side marker verification independently of
// the production seqovlMarker, so the test fails if the wire contract drifts.
func recomputeMarker(secret, nonce []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(seqovlDecoySalt))
	mac.Write(nonce)
	return mac.Sum(nil)[:seqovlMarkerLen]
}

func TestBuildSeqovlDecoyStructure(t *testing.T) {
	secret := []byte("shared-secret-abc")
	rec := buildSeqovlDecoy(secret)

	if len(rec) < 5+seqovlMinJunk+seqovlNonceLen+seqovlMarkerLen {
		t.Fatalf("decoy too short: %d", len(rec))
	}
	if rec[0] != 0x16 {
		t.Fatalf("decoy content type = 0x%02x, want 0x16 (handshake)", rec[0])
	}
	recordLen := int(rec[3])<<8 | int(rec[4])
	if 5+recordLen != len(rec) {
		t.Fatalf("record length mismatch: header says %d, record body %d", recordLen, len(rec)-5)
	}

	payload := rec[5:]
	nonce := payload[0:seqovlNonceLen]
	marker := payload[seqovlNonceLen : seqovlNonceLen+seqovlMarkerLen]

	if nonce[0] == 0x01 {
		t.Fatalf("nonce[0] == 0x01 would be misread as a ClientHello handshake type")
	}
	if !hmac.Equal(marker, recomputeMarker(secret, nonce)) {
		t.Fatalf("marker does not verify against HMAC(secret, salt||nonce)")
	}
}

func TestSeqovlMarkerRejectsWrongSecret(t *testing.T) {
	rec := buildSeqovlDecoy([]byte("secret-one"))
	payload := rec[5:]
	nonce := payload[0:seqovlNonceLen]
	marker := payload[seqovlNonceLen : seqovlNonceLen+seqovlMarkerLen]

	if hmac.Equal(marker, recomputeMarker([]byte("secret-two"), nonce)) {
		t.Fatal("marker verified under a different secret — DPI could forge it")
	}
}

func TestBuildSeqovlDecoyRandomized(t *testing.T) {
	secret := []byte("shared-secret-abc")
	a := buildSeqovlDecoy(secret)
	b := buildSeqovlDecoy(secret)

	if bytes.Equal(a, b) {
		t.Fatal("two decoys are identical — per-connection randomization missing")
	}
	// Different nonces should be the norm; length may occasionally collide but
	// the full records must differ.
	if bytes.Equal(a[5:5+seqovlNonceLen], b[5:5+seqovlNonceLen]) {
		t.Fatal("two decoys share the same nonce")
	}
}

// TestSeqovlConnPrependsDecoy verifies seqovlConn writes the decoy record before
// the first real payload, and that the real payload arrives intact afterwards.
func TestSeqovlConnPrependsDecoy(t *testing.T) {
	secret := []byte("shared-secret-abc")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := newSeqovlConn(client, secret)

	realFlight := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}

	go func() {
		// First write triggers decoy prefix, second write is a plain pass-through.
		_, _ = sc.Write(realFlight)
		_, _ = sc.Write([]byte("more-data"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the decoy TLS record.
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatalf("read decoy header: %v", err)
	}
	if hdr[0] != 0x16 {
		t.Fatalf("decoy content type = 0x%02x, want 0x16", hdr[0])
	}
	decoyLen := int(hdr[3])<<8 | int(hdr[4])
	decoyBody := make([]byte, decoyLen)
	if _, err := io.ReadFull(server, decoyBody); err != nil {
		t.Fatalf("read decoy body: %v", err)
	}
	nonce := decoyBody[0:seqovlNonceLen]
	marker := decoyBody[seqovlNonceLen : seqovlNonceLen+seqovlMarkerLen]
	if !hmac.Equal(marker, recomputeMarker(secret, nonce)) {
		t.Fatal("decoy on the wire did not verify")
	}

	// Then the real first flight, byte-for-byte.
	got := make([]byte, len(realFlight))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read real flight: %v", err)
	}
	if !bytes.Equal(got, realFlight) {
		t.Fatalf("real flight corrupted: got %x want %x", got, realFlight)
	}

	// And the trailing pass-through write.
	tail := make([]byte, len("more-data"))
	if _, err := io.ReadFull(server, tail); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if string(tail) != "more-data" {
		t.Fatalf("tail corrupted: %q", tail)
	}
}

func TestSeqovlStrategyMetadata(t *testing.T) {
	s := NewSeqovlStrategy(nil, []byte("secret"), false)
	if s.ID() != "seqovl" {
		t.Fatalf("ID = %q, want seqovl", s.ID())
	}
	if !s.RequiresServer() {
		t.Fatal("RequiresServer should be true")
	}
	// Must rank below REALITY (priority 5) so it never preempts the default.
	if s.Priority() <= (&REALITYStrategy{}).Priority() {
		t.Fatalf("seqovl priority %d must be > REALITY priority %d", s.Priority(), (&REALITYStrategy{}).Priority())
	}
}
