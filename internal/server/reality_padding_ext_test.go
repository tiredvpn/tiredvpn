package server

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// A ClientHello carrying a genuine padding extension used to kill the
// connection: the server answered with a FIN and nothing else - no ServerHello,
// no alert. That broke two things at once.
//
// Availability: OpenSSL pads any ClientHello between 256 and 511 bytes up to
// 512, a workaround for an old F5 bug, so ordinary clients land in that range
// routinely and could not reach the server at all.
//
// Detectability: it made one packet enough to pick our servers out. Send a
// ClientHello with extension 21, see whether a ServerHello comes back. No
// statistics, no JARM, no burst analysis - and every real site answers
// normally.
//
// The cause is that REALITY hides its credentials in that same extension and
// the wire format carries no magic, so the detector cannot tell a real padding
// extension from ours. It does not have to: what matters is that failing to
// authenticate returns the connection to the ordinary path instead of dropping
// it.

// helloWithPadding builds a TLS 1.3 ClientHello padded to total bytes with a
// real RFC 7685 padding extension, the way OpenSSL would.
func helloWithPadding(t *testing.T, sni string, total int) []byte {
	t.Helper()

	var exts []byte

	// server_name
	if sni != "" {
		name := []byte(sni)
		sniBody := []byte{0x00}
		sniBody = binary.BigEndian.AppendUint16(sniBody, uint16(len(name)))
		sniBody = append(sniBody, name...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(sniBody)))
		list = append(list, sniBody...)
		exts = binary.BigEndian.AppendUint16(exts, 0x0000)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(list)))
		exts = append(exts, list...)
	}

	// supported_versions: TLS 1.3
	sv := []byte{0x02, 0x03, 0x04}
	exts = binary.BigEndian.AppendUint16(exts, 0x002b)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sv)))
	exts = append(exts, sv...)

	body := func(padLen int) []byte {
		e := append([]byte(nil), exts...)
		if padLen >= 0 {
			e = binary.BigEndian.AppendUint16(e, 0x0015)
			e = binary.BigEndian.AppendUint16(e, uint16(padLen))
			e = append(e, make([]byte, padLen)...)
		}
		b := []byte{0x03, 0x03}
		b = append(b, bytes.Repeat([]byte{0x42}, 32)...) // random
		b = append(b, 32)
		b = append(b, bytes.Repeat([]byte{0x43}, 32)...) // session_id
		b = binary.BigEndian.AppendUint16(b, 2)
		b = binary.BigEndian.AppendUint16(b, 0x1301)
		b = append(b, 1, 0)
		b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
		return append(b, e...)
	}

	// Size the padding so the finished record hits exactly `total`.
	bare := len(body(-1)) + 4 + 5 // handshake header + record header
	padLen := total - bare - 4    // the padding extension's own header
	if padLen < 0 {
		t.Fatalf("cannot build a %d-byte hello: the bare one is already %d", total, bare)
	}

	b := body(padLen)
	hs := []byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	hs = append(hs, b...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// answersClientHello sends raw ClientHello bytes to a server and reports
// whether anything came back before the peer closed.
func answersClientHello(t *testing.T, srvCtx *serverContext, hello []byte) (answered bool, first []byte) {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(server, srvCtx, 1)
	}()

	if _, err := client.Write(hello); err != nil {
		t.Fatalf("writing ClientHello: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.Close()
	<-done

	if err != nil || n == 0 {
		return false, nil
	}
	return true, buf[:n]
}

// b1PaddingCtx builds a server context with no cover domain, which is the
// configuration the production fronts run and the one that dropped the
// connection.
func b1PaddingCtx(t *testing.T, legacy, b1 bool) *serverContext {
	t.Helper()
	cfg := &Config{
		Secret:               []byte("a-secret-no-prober-has"),
		REALITYLegacyEnabled: legacy,
		REALITYB1Enabled:     b1,
		REALITYCoverDomain:   "", // deliberately empty: this is the broken case
	}
	return &serverContext{
		cfg: cfg,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{selfSignedCertForTest(t)},
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// TestPaddingExtensionGetsAnAnswer is the regression test for the distinguisher:
// a ClientHello with a real padding extension must get a TLS answer, not a FIN.
func TestPaddingExtensionGetsAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		legacy, b1 bool
	}{
		{"legacy only", true, false},
		{"b1 only", false, true},
		{"both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvCtx := b1PaddingCtx(t, tc.legacy, tc.b1)
			hello := helloWithPadding(t, "www.microsoft.com", 512)

			answered, first := answersClientHello(t, srvCtx, hello)
			if !answered {
				t.Fatal("the server closed without answering a ClientHello that carries a " +
					"padding extension; that is both an availability bug and a one-packet distinguisher")
			}
			// A handshake record or an alert both count as an answer. Silence
			// is the thing that singles us out.
			if first[0] != 0x16 && first[0] != 0x15 {
				t.Fatalf("first byte of the answer is %#x, want a handshake or alert record", first[0])
			}
		})
	}
}

// TestPaddingExtensionAcrossHelloSizes sweeps the range OpenSSL pads into. Only
// two points were known before: 512 dropped, 238 passed.
func TestPaddingExtensionAcrossHelloSizes(t *testing.T) {
	srvCtx := b1PaddingCtx(t, true, true)

	for _, size := range []int{200, 256, 300, 384, 450, 511, 512, 600, 900} {
		t.Run("", func(t *testing.T) {
			hello := helloWithPadding(t, "www.microsoft.com", size)
			if len(hello) != size {
				t.Fatalf("built a %d-byte hello, wanted %d", len(hello), size)
			}
			answered, _ := answersClientHello(t, srvCtx, hello)
			if !answered {
				t.Fatalf("a %d-byte ClientHello with padding got no answer", size)
			}
		})
	}
}

// TestHelloWithoutPaddingStillAnswers is the control: the same hello without
// the extension always worked, and must keep working.
func TestHelloWithoutPaddingStillAnswers(t *testing.T) {
	srvCtx := b1PaddingCtx(t, true, true)

	var exts []byte
	sv := []byte{0x02, 0x03, 0x04}
	exts = binary.BigEndian.AppendUint16(exts, 0x002b)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sv)))
	exts = append(exts, sv...)

	b := []byte{0x03, 0x03}
	b = append(b, bytes.Repeat([]byte{0x42}, 32)...)
	b = append(b, 32)
	b = append(b, bytes.Repeat([]byte{0x43}, 32)...)
	b = binary.BigEndian.AppendUint16(b, 2)
	b = binary.BigEndian.AppendUint16(b, 0x1301)
	b = append(b, 1, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(exts)))
	b = append(b, exts...)

	hs := append([]byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
	hello := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)

	if answered, _ := answersClientHello(t, srvCtx, hello); !answered {
		t.Fatal("a ClientHello without padding got no answer")
	}
}
