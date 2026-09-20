package strategy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const wireTestSecret = "confusion-wire-test-secret-32b!!"

var allConfusionVariants = []byte{
	confusionVariantDNS,
	confusionVariantHTTP,
	confusionVariantSSH,
	confusionVariantSMTP,
	confusionVariantGRPC,
}

func variantName(v byte) string {
	switch v {
	case confusionVariantDNS:
		return "dns"
	case confusionVariantHTTP:
		return "http"
	case confusionVariantSSH:
		return "ssh"
	case confusionVariantSMTP:
		return "smtp"
	case confusionVariantGRPC:
		return "grpc-web"
	}
	return "?"
}

// TestConfusionCarrierRoundTrip drives all five variants through build, parse,
// marker check and answer. A variant that regresses in either direction shows
// up here rather than as a dead transport in the field.
func TestConfusionCarrierRoundTrip(t *testing.T) {
	secret := []byte(wireTestSecret)

	for _, variant := range allConfusionVariants {
		t.Run(variantName(variant), func(t *testing.T) {
			nonce, err := NewConfusionNonce()
			if err != nil {
				t.Fatalf("nonce: %v", err)
			}
			marker := ConfusionClientMarker(secret, nonce[:], variant)
			if len(marker) < confusionMarkerMinLen || len(marker) > confusionMarkerMaxLen {
				t.Fatalf("marker length %d outside [%d,%d]", len(marker), confusionMarkerMinLen, confusionMarkerMaxLen)
			}

			payload := []byte("the-first-sealed-frame-stands-in-here")
			req, err := BuildConfusionRequest(variant, nonce[:], marker, payload)
			if err != nil {
				t.Fatalf("BuildConfusionRequest: %v", err)
			}

			// Trailing bytes must not confuse the parser: a real socket hands
			// the carrier and the frames after it in one read.
			withTail := append(append([]byte{}, req...), []byte("trailing-sealed-bytes")...)

			carrier, err := ParseConfusionRequest(withTail)
			if err != nil {
				t.Fatalf("ParseConfusionRequest: %v", err)
			}
			if carrier.Variant != variant {
				t.Fatalf("variant = %d, want %d", carrier.Variant, variant)
			}
			if carrier.Length != len(req) {
				t.Errorf("Length = %d, want %d", carrier.Length, len(req))
			}
			if !bytes.Equal(carrier.Nonce, nonce[:]) {
				t.Errorf("nonce did not survive the round trip")
			}
			markerLen, ok := MatchConfusionClientMarker(secret, carrier.Nonce, carrier.Variant, carrier.Body)
			if !ok {
				t.Fatal("marker does not verify")
			}
			if got := carrier.Body[markerLen:]; !bytes.Equal(got, payload) {
				t.Errorf("payload = %q, want %q", got, payload)
			}

			// The answering direction.
			srvMarker := ConfusionServerMarker(secret, carrier.Nonce, carrier.Variant)
			respPayload := []byte("server-frame")
			resp, err := BuildConfusionResponse(carrier, srvMarker, respPayload)
			if err != nil {
				t.Fatalf("BuildConfusionResponse: %v", err)
			}
			respCarrier, err := ParseConfusionResponse(variant, append(append([]byte{}, resp...), 'X'))
			if err != nil {
				t.Fatalf("ParseConfusionResponse: %v", err)
			}
			if respCarrier.Length != len(resp) {
				t.Errorf("response Length = %d, want %d", respCarrier.Length, len(resp))
			}
			if !bytes.HasPrefix(respCarrier.Body, srvMarker) {
				t.Error("server marker missing from the answer")
			}
			if got := respCarrier.Body[len(srvMarker):]; !bytes.Equal(got, respPayload) {
				t.Errorf("response payload = %q, want %q", got, respPayload)
			}
		})
	}
}

// TestConfusionCarrierParsesAsItsProtocol checks each carrier with a parser
// that knows nothing about us - the standard library's HTTP reader and x/net's
// DNS message parser. v1 would have failed both: its DNS message carried bytes
// past the question that no count declared, and its HTTP request had a body
// with no Content-Length.
func TestConfusionCarrierParsesAsItsProtocol(t *testing.T) {
	secret := []byte(wireTestSecret)
	payload := bytes.Repeat([]byte{0xA5}, 64)

	build := func(t *testing.T, variant byte) ([]byte, []byte) {
		t.Helper()
		nonce, err := NewConfusionNonce()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		marker := ConfusionClientMarker(secret, nonce[:], variant)
		req, err := BuildConfusionRequest(variant, nonce[:], marker, payload)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return req, nonce[:]
	}

	t.Run("dns", func(t *testing.T) {
		req, _ := build(t, confusionVariantDNS)
		if got := int(binary.BigEndian.Uint16(req[:2])); got != len(req)-2 {
			t.Fatalf("DNS-over-TCP length prefix = %d, message is %d bytes", got, len(req)-2)
		}

		var p dnsmessage.Parser
		hdr, err := p.Start(req[2:])
		if err != nil {
			t.Fatalf("dnsmessage.Start: %v", err)
		}
		if hdr.Response {
			t.Error("query carries the response bit")
		}
		if !hdr.RecursionDesired {
			t.Error("query without RD is not what a stub resolver sends")
		}
		qs, err := p.AllQuestions()
		if err != nil {
			t.Fatalf("AllQuestions: %v", err)
		}
		if len(qs) != 1 {
			t.Fatalf("questions = %d, want 1", len(qs))
		}
		if _, err := p.AllAnswers(); err != nil {
			t.Fatalf("AllAnswers: %v", err)
		}
		if _, err := p.AllAuthorities(); err != nil {
			t.Fatalf("AllAuthorities: %v", err)
		}
		ars, err := p.AllAdditionals()
		if err != nil {
			t.Fatalf("AllAdditionals: %v", err)
		}
		if len(ars) != 1 {
			t.Fatalf("additionals = %d, want 1 (the OPT record)", len(ars))
		}
		if ars[0].Header.Type != dnsmessage.TypeOPT {
			t.Errorf("additional is type %v, want OPT", ars[0].Header.Type)
		}
		opt, ok := ars[0].Body.(*dnsmessage.OPTResource)
		if !ok {
			t.Fatalf("additional body is %T, want *dnsmessage.OPTResource", ars[0].Body)
		}
		if len(opt.Options) != 1 || opt.Options[0].Code != confusionEDNSOptionCode {
			t.Errorf("OPT options = %+v, want one local-use option %d", opt.Options, confusionEDNSOptionCode)
		}
		// Nothing may follow the message inside the declared length.
		if err := p.SkipAllAdditionals(); err != nil {
			t.Errorf("trailing bytes after the additional section: %v", err)
		}
	})

	t.Run("http", func(t *testing.T) {
		req, _ := build(t, confusionVariantHTTP)
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req)))
		if err != nil {
			t.Fatalf("http.ReadRequest: %v", err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if int64(len(body)) != r.ContentLength {
			t.Errorf("body is %d bytes, Content-Length says %d", len(body), r.ContentLength)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST (a GET with a body is what v1 sent)", r.Method)
		}
	})

	t.Run("grpc-web", func(t *testing.T) {
		req, _ := build(t, confusionVariantGRPC)
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req)))
		if err != nil {
			t.Fatalf("http.ReadRequest: %v", err)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "grpc-web") {
			t.Errorf("Content-Type = %q, want a grpc-web type", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if len(body) < 5 {
			t.Fatalf("body = %d bytes, too short for a gRPC frame", len(body))
		}
		frameLen := int(binary.BigEndian.Uint32(body[1:5]))
		if frameLen == 0 {
			t.Fatal("gRPC frame length is zero in front of a non-empty message (the v1 defect)")
		}
		if 5+frameLen != len(body) {
			t.Errorf("gRPC frame declares %d bytes, body carries %d", frameLen, len(body)-5)
		}
		msg := body[5:]
		if msg[0] != 0x0a {
			t.Errorf("protobuf tag = 0x%02x, want 0x0a (field 1, wire type 2)", msg[0])
		}
		fieldLen, n, ok := readProtoVarint(msg[1:])
		if !ok {
			t.Fatal("protobuf length varint does not decode")
		}
		if 1+n+int(fieldLen) != len(msg) {
			t.Errorf("protobuf field declares %d bytes, message carries %d", fieldLen, len(msg)-1-n)
		}
	})

	t.Run("ssh", func(t *testing.T) {
		req, _ := build(t, confusionVariantSSH)
		nl := bytes.Index(req, []byte("\r\n"))
		if nl < 0 || !bytes.HasPrefix(req, []byte("SSH-2.0-")) {
			t.Fatal("no SSH identification string")
		}
		off := nl + 2
		for i := 0; i < 2; i++ {
			if off+5 > len(req) {
				t.Fatalf("packet %d: truncated", i)
			}
			pktLen := int(binary.BigEndian.Uint32(req[off : off+4]))
			padLen := int(req[off+4])
			if (4+pktLen)%confSSHBlockSize != 0 {
				t.Errorf("packet %d: 4+packet_length = %d is not a multiple of %d",
					i, 4+pktLen, confSSHBlockSize)
			}
			if padLen < confSSHMinPadding {
				t.Errorf("packet %d: padding_length = %d, RFC 4253 requires at least 4", i, padLen)
			}
			if i == 0 && req[off+5] != confSSHMsgKexInit {
				t.Errorf("first packet is msg %d, want KEXINIT", req[off+5])
			}
			if i == 0 {
				// A KEXINIT whose name-lists are all empty is what v1 sent and
				// what no implementation sends.
				if pktLen < 300 {
					t.Errorf("KEXINIT is %d bytes; a real one carries algorithm names", pktLen)
				}
			}
			off += 4 + pktLen
		}
		if off != len(req) {
			t.Errorf("%d bytes left over after two SSH packets", len(req)-off)
		}
	})

	t.Run("smtp", func(t *testing.T) {
		req, _ := build(t, confusionVariantSMTP)
		lines := strings.Split(string(req), "\r\n")
		if len(lines) < 3 || lines[len(lines)-1] != "" {
			t.Fatalf("SMTP carrier is not CRLF-terminated lines: %q", req)
		}
		if !strings.HasPrefix(lines[0], "EHLO ") {
			t.Errorf("first line = %q, want an EHLO", lines[0])
		}
		if !strings.HasPrefix(lines[1], "AUTH PLAIN ") {
			t.Errorf("second line = %q, want AUTH PLAIN", lines[1])
		}
		if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines[1], "AUTH PLAIN ")); err != nil {
			t.Errorf("SASL initial response is not base64: %v", err)
		}
		for i, l := range lines[:len(lines)-1] {
			if len(l)+2 > 12288 {
				t.Errorf("line %d is %d bytes, past the RFC 4954 ceiling", i, len(l)+2)
			}
		}
	})
}

// TestConfusionMarkerDiffersPerConnection pins the nonce doing its job: the
// same client, the same secret, the same variant, two connections, two
// different markers. A constant marker would be the literal "TIRED" again,
// only longer.
func TestConfusionMarkerDiffersPerConnection(t *testing.T) {
	secret := []byte(wireTestSecret)

	firsts := make([][]byte, 2)
	for i := range firsts {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		cc, err := NewConfusedConn(client, ConfusionHTTPoverTLS, secret)
		if err != nil {
			t.Fatalf("NewConfusedConn: %v", err)
		}
		go cc.Write([]byte("same payload both times"))

		buf := make([]byte, 4096)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		firsts[i] = append([]byte{}, buf[:n]...)
	}

	a, err := ParseConfusionRequest(firsts[0])
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	b, err := ParseConfusionRequest(firsts[1])
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatal("two connections reused one nonce")
	}

	aLen, ok := MatchConfusionClientMarker(secret, a.Nonce, a.Variant, a.Body)
	if !ok {
		t.Fatal("first marker does not verify")
	}
	bLen, ok := MatchConfusionClientMarker(secret, b.Nonce, b.Variant, b.Body)
	if !ok {
		t.Fatal("second marker does not verify")
	}
	if bytes.Equal(a.Body[:aLen], b.Body[:bLen]) {
		t.Fatal("two connections produced the same marker")
	}

	// Cross-check: a marker is bound to its own nonce, so swapping them fails.
	if _, ok := MatchConfusionClientMarker(secret, b.Nonce, a.Variant, a.Body); ok {
		t.Error("first marker verified under the second connection's nonce")
	}
}

// TestConfusionMarkerBoundToVariant pins the variant byte in the derivation: a
// marker minted for one carrier must not pass inside another, or a captured
// packet could be replayed into whichever variant the server parses loosest.
func TestConfusionMarkerBoundToVariant(t *testing.T) {
	secret := []byte(wireTestSecret)
	nonce, _ := NewConfusionNonce()

	body := ConfusionClientMarker(secret, nonce[:], confusionVariantDNS)
	for _, other := range allConfusionVariants {
		if other == confusionVariantDNS {
			continue
		}
		if _, ok := MatchConfusionClientMarker(secret, nonce[:], other, body); ok {
			t.Errorf("DNS marker verified as variant %s", variantName(other))
		}
	}
}

// TestConfusionWrongSecretRejected is the negative half of the marker check.
func TestConfusionWrongSecretRejected(t *testing.T) {
	nonce, _ := NewConfusionNonce()
	body := ConfusionClientMarker([]byte(wireTestSecret), nonce[:], confusionVariantSMTP)

	if _, ok := MatchConfusionClientMarker([]byte("a-different-secret"), nonce[:], confusionVariantSMTP, body); ok {
		t.Fatal("marker verified under a secret that did not produce it")
	}
	if _, ok := MatchConfusionClientMarker(nil, nonce[:], confusionVariantSMTP, body); ok {
		t.Fatal("marker verified with no secret at all")
	}
}

// TestConfusionPayloadNeverInTheClear is the plaintext test. v1 length-prefixed
// raw bytes in both directions, so every byte of a user's traffic was readable
// on the wire; the positive control for it is the assertion at the bottom, which
// shows the same needle IS found when it is not sealed.
func TestConfusionPayloadNeverInTheClear(t *testing.T) {
	secret := []byte(wireTestSecret)
	needle := []byte("GET /secret-document HTTP/1.1\r\nHost: example.invalid\r\n\r\n")

	for _, variant := range allConfusionVariants {
		t.Run(variantName(variant), func(t *testing.T) {
			client, server := wireTCPPair(t)

			cc, err := NewConfusedConn(client, ConfusionType(variant), secret)
			if err != nil {
				t.Fatalf("NewConfusedConn: %v", err)
			}

			// Both writes matter and for different reasons: the first goes out
			// inside the carrier, the second takes the plain record path. A
			// read loop that stops on a byte count would miss the second one,
			// which is exactly where a regression would sit.
			if _, err := cc.Write(needle); err != nil {
				t.Fatalf("first write: %v", err)
			}
			if _, err := cc.Write(needle); err != nil {
				t.Fatalf("second write: %v", err)
			}
			client.Close()

			server.SetReadDeadline(time.Now().Add(5 * time.Second))
			seen, _ := io.ReadAll(server)
			if len(seen) < 2*len(needle) {
				t.Fatalf("read %d bytes for two %d-byte writes; the reader missed part of the stream",
					len(seen), len(needle))
			}

			if bytes.Contains(seen, needle) {
				t.Error("payload appears on the wire in the clear")
			}
			// Even a distinctive fragment must not survive.
			if bytes.Contains(seen, []byte("secret-document")) {
				t.Error("payload fragment appears on the wire in the clear")
			}

			// Positive control: the needle is findable by this method when it
			// is not sealed, so a pass above means the sealing worked rather
			// than that the search is blind.
			if !bytes.Contains(append(append([]byte{}, seen...), needle...), needle) {
				t.Fatal("positive control failed: the search cannot find the needle at all")
			}
		})
	}
}

// TestConfusionSealedStreamEndToEnd runs the two ends against each other over a
// socket pair: client carrier, server answer, then traffic both ways.
func TestConfusionSealedStreamEndToEnd(t *testing.T) {
	secret := []byte(wireTestSecret)

	for _, variant := range allConfusionVariants {
		t.Run(variantName(variant), func(t *testing.T) {
			clientSock, serverSock := net.Pipe()
			defer clientSock.Close()
			defer serverSock.Close()

			cc, err := NewConfusedConn(clientSock, ConfusionType(variant), secret)
			if err != nil {
				t.Fatalf("NewConfusedConn: %v", err)
			}

			clientDone := make(chan error, 1)
			go func() {
				if _, err := cc.Write([]byte("hello from the client")); err != nil {
					clientDone <- err
					return
				}
				got := make([]byte, 64)
				n, err := cc.Read(got)
				if err != nil {
					clientDone <- err
					return
				}
				if string(got[:n]) != "hello from the server" {
					clientDone <- errors.New("server payload mismatch: " + string(got[:n]))
					return
				}
				clientDone <- nil
			}()

			req, leftover, _, err := ReadConfusionRequest(serverSock, nil)
			if err != nil {
				t.Fatalf("ReadConfusionRequest: %v", err)
			}
			markerLen, ok := MatchConfusionClientMarker(secret, req.Nonce, req.Variant, req.Body)
			if !ok {
				t.Fatal("server could not verify the client marker")
			}
			sc, err := NewConfusionServerConn(serverSock, req, secret, req.Body[markerLen:], leftover)
			if err != nil {
				t.Fatalf("NewConfusionServerConn: %v", err)
			}

			frame, err := sc.ReadFrame()
			if err != nil {
				t.Fatalf("server ReadFrame: %v", err)
			}
			if string(frame) != "hello from the client" {
				t.Fatalf("server got %q", frame)
			}
			if _, err := sc.Write([]byte("hello from the server")); err != nil {
				t.Fatalf("server Write: %v", err)
			}

			if err := <-clientDone; err != nil {
				t.Fatalf("client: %v", err)
			}
		})
	}
}

// TestConfusionTamperIsSticky pins the AEAD doing what a bare keystream cannot:
// a flipped bit breaks the connection and keeps it broken.
func TestConfusionTamperIsSticky(t *testing.T) {
	secret := []byte(wireTestSecret)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	nonce, _ := NewConfusionNonce()
	writer, err := NewConfusionConn(a, secret, nonce[:], confusionVariantHTTP, true)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	reader, err := NewConfusionConn(b, secret, nonce[:], confusionVariantHTTP, false)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}

	frames := writer.SealFrames([]byte("tamper with me"))
	frames[len(frames)-1] ^= 0x01 // flip a bit in the tag

	go func() {
		a.Write(frames)
		a.Write(writer.SealFrames([]byte("and this one is intact")))
	}()

	if _, err := reader.ReadFrame(); !errors.Is(err, ErrConfusionAuth) {
		t.Fatalf("tampered frame opened: err = %v", err)
	}
	if _, err := reader.ReadFrame(); !errors.Is(err, ErrConfusionAuth) {
		t.Fatalf("read side recovered after tampering: err = %v", err)
	}
}

// TestDetectConfusionRejectsNoise pins the narrowing. Every input here was
// accepted by the 1.10.0 detector or by the handler behind it.
func TestParseConfusionRequestRejectsNoise(t *testing.T) {
	legacyDNS := func() []byte {
		// The 1.10.0 DNS carrier: header, question, then "\0\0TIRED" and a
		// length-prefixed payload that no section count declares.
		var msg bytes.Buffer
		msg.Write([]byte{0x12, 0x34, 0x01, 0x00})
		msg.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		msg.Write(encodeDNSName("yandex.ru"))
		msg.Write([]byte{0x00, 0x01, 0x00, 0x01})
		msg.Write([]byte{0x00, 0x00, 'T', 'I', 'R', 'E', 'D'})
		msg.Write([]byte{0x00, 0x00, 0x00, 0x08})
		msg.Write([]byte("\x00\x06host:1"))
		out := make([]byte, 2+msg.Len())
		binary.BigEndian.PutUint16(out[:2], uint16(msg.Len()))
		copy(out[2:], msg.Bytes())
		return out
	}()

	tests := []struct {
		name string
		data []byte
	}{
		{"the bare TIRED literal", []byte("TIRED\x00\x00\x00\x08\x00\x06host:1")},
		{"the 1.10.0 DNS carrier", legacyDNS},
		{"the 1.10.0 HTTP carrier",
			[]byte("GET / HTTP/1.1\r\nHost: yandex.ru\r\n\r\nTIRED\x00\x00\x00\x08\x00\x06host:1")},
		{"the 1.10.0 SMTP carrier",
			[]byte("EHLO yandex.ru\r\n\x00\x00TIRED\x00\x00\x00\x08\x00\x06host:1")},
		{"anything whose fifth and sixth bytes read 0x01 0x00",
			append([]byte{0x00, 0x40, 0xde, 0xad, 0x01, 0x00}, bytes.Repeat([]byte{0x41}, 64)...)},
		{"an HTTP/1.1 GET", []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"a TLS ClientHello", append([]byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"),
			bytes.Repeat([]byte{0x7f}, 32)...)},
		{"the HTTP/2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")},
		{"random bytes", bytes.Repeat([]byte{0x5a}, 300)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfusionRequest(tt.data)
			if err == nil {
				t.Fatal("accepted as a confusion carrier")
			}
			if errors.Is(err, ErrConfusionNeedMore) {
				t.Fatalf("asked for more bytes instead of rejecting: %v", err)
			}
		})
	}
}

// TestConfusionCarrierSplitAcrossReads pins the incremental path: a carrier
// delivered one byte at a time must parse exactly as it does in one piece.
func TestConfusionCarrierSplitAcrossReads(t *testing.T) {
	secret := []byte(wireTestSecret)

	for _, variant := range allConfusionVariants {
		t.Run(variantName(variant), func(t *testing.T) {
			nonce, _ := NewConfusionNonce()
			marker := ConfusionClientMarker(secret, nonce[:], variant)
			req, err := BuildConfusionRequest(variant, nonce[:], marker, []byte("payload"))
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			carrier, leftover, consumed, err := ReadConfusionCarrier(
				iotest1ByteReader(append(append([]byte{}, req...), []byte("tail")...)),
				nil, ParseConfusionRequest)
			if err != nil {
				t.Fatalf("ReadConfusionCarrier: %v", err)
			}
			if carrier.Variant != variant {
				t.Errorf("variant = %d, want %d", carrier.Variant, variant)
			}
			if _, ok := MatchConfusionClientMarker(secret, carrier.Nonce, carrier.Variant, carrier.Body); !ok {
				t.Error("marker does not verify after a split read")
			}
			if !bytes.HasPrefix(consumed, req) {
				t.Error("consumed bytes do not start with the carrier")
			}
			// A one-byte-at-a-time reader stops the moment the carrier is
			// complete, so nothing of the tail has been read yet.
			if len(consumed) != carrier.Length {
				t.Errorf("consumed %d bytes for a %d-byte carrier", len(consumed), carrier.Length)
			}
			if len(leftover) != 0 {
				t.Errorf("leftover = %q, want nothing read past the carrier", leftover)
			}
		})
	}
}

type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func iotest1ByteReader(data []byte) io.Reader { return &oneByteReader{data: data} }

// wireTCPPair returns a connected pair of real TCP sockets. A net.Pipe is
// unbuffered, so a test that writes twice before reading would deadlock on the
// pipe rather than on anything under test.
func wireTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() {
		client.Close()
		r.c.Close()
	})
	return client, r.c
}

// TestConfusionMarkerLengthVaries pins the marker length being derived rather
// than fixed. A constant length would put a constant-size block at a constant
// offset in every opening packet, which is most of what made "TIRED" easy.
//
// What this test does NOT assert is that the resulting length distribution
// resembles anything real. It is flat over [16,48) by construction, and there
// is no measurement of EDNS0 option lengths, SASL initial-response lengths or
// SSH string lengths in this repository to compare it against. Rule 3 asks for
// that comparison to be named; here it is named as absent.
func TestConfusionMarkerLengthVaries(t *testing.T) {
	secret := []byte(wireTestSecret)
	seen := map[int]int{}

	for i := 0; i < 2000; i++ {
		nonce, err := NewConfusionNonce()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		n := len(ConfusionClientMarker(secret, nonce[:], confusionVariantDNS))
		if n < confusionMarkerMinLen || n > confusionMarkerMaxLen {
			t.Fatalf("marker length %d outside [%d,%d]", n, confusionMarkerMinLen, confusionMarkerMaxLen)
		}
		seen[n]++
	}

	if len(seen) < confusionMarkerSpan {
		t.Fatalf("marker length took %d of %d possible values in 2000 draws; it is not being derived",
			len(seen), confusionMarkerSpan)
	}
}
