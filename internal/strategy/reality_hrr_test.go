package strategy

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// serverHelloRecord builds a minimal but structurally valid ServerHello record
// with the given 32-byte random.
func serverHelloRecord(random []byte) []byte {
	body := make([]byte, 0, 64)
	body = append(body, 0x02)             // handshake type: ServerHello
	body = append(body, 0x00, 0x00, 0x26) // handshake length (2 version + 32 random + 4 tail)
	body = append(body, 0x03, 0x03)       // legacy_version
	body = append(body, random...)
	body = append(body, 0x00, 0x00, 0x13, 0x01) // session id len, cipher suite

	record := []byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	return append(record, body...)
}

func TestIsHelloRetryRequest(t *testing.T) {
	if !isHelloRetryRequest(serverHelloRecord(helloRetryRequestRandom[:])) {
		t.Error("HelloRetryRequest not recognised")
	}

	ordinary := bytes.Repeat([]byte{0xAB}, 32)
	if isHelloRetryRequest(serverHelloRecord(ordinary)) {
		t.Error("ordinary ServerHello misread as HelloRetryRequest")
	}

	// One flipped bit in the sentinel must not match.
	nearMiss := append([]byte(nil), helloRetryRequestRandom[:]...)
	nearMiss[31] ^= 0x01
	if isHelloRetryRequest(serverHelloRecord(nearMiss)) {
		t.Error("near-miss random matched the HelloRetryRequest sentinel")
	}
}

func TestIsHelloRetryRequestRejectsMalformed(t *testing.T) {
	full := serverHelloRecord(helloRetryRequestRandom[:])

	for _, tc := range []struct {
		name   string
		record []byte
	}{
		{"empty", nil},
		{"truncated before random", full[:20]},
		{"not a handshake record", append([]byte{0x17}, full[1:]...)},
		{"not a ServerHello", append(append([]byte(nil), full[:5]...), append([]byte{0x01}, full[6:]...)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isHelloRetryRequest(tc.record) {
				t.Error("accepted a record that is not a HelloRetryRequest")
			}
		})
	}
}

// TestHandleHelloRetryRequestSendsAlert pins the observable behaviour: a probe
// that injects a HRR sees a TLS alert, the way a browser refusing an
// unsatisfiable retry would, not a bare connection drop.
func TestHandleHelloRetryRequestSendsAlert(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	r := &REALITYStrategy{}
	go func() {
		r.handleHelloRetryRequest(client, "github.com:443")
		client.Close()
	}()

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, 7)
	if _, err := readFull(server, got); err != nil {
		t.Fatalf("reading alert: %v", err)
	}

	// alert(21), TLS 1.2 legacy version, length 2, fatal(2), illegal_parameter(47)
	want := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2F}
	if !bytes.Equal(got, want) {
		t.Fatalf("alert record = % x, want % x", got, want)
	}
}
