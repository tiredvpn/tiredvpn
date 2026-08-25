package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// tlsExtension is one entry of a TLS extension list.
type tlsExtension struct {
	typ  uint16
	body []byte
}

// marshalExtensions serialises an extension list: [type:2][len:2][body].
func marshalExtensions(exts []tlsExtension) []byte {
	var buf bytes.Buffer
	for _, e := range exts {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], e.typ)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(e.body)))
		buf.Write(hdr[:])
		buf.Write(e.body)
	}
	return buf.Bytes()
}

// clientHelloBody builds a well-formed ClientHello body (everything after the
// 4-byte handshake header) carrying the given extension list.
func clientHelloBody(exts []tlsExtension) []byte {
	extBytes := marshalExtensions(exts)

	var b bytes.Buffer
	b.Write([]byte{0x03, 0x03})             // legacy_version TLS 1.2
	b.Write(bytes.Repeat([]byte{0x11}, 32)) // random
	b.WriteByte(32)                         // session id length
	b.Write(bytes.Repeat([]byte{0x22}, 32)) // session id
	b.Write([]byte{0x00, 0x04})             // cipher suites length
	b.Write([]byte{0x13, 0x01, 0x13, 0x02})
	b.WriteByte(0x01) // compression methods length
	b.WriteByte(0x00) // null compression
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extBytes)))
	b.Write(extLen[:])
	b.Write(extBytes)
	return b.Bytes()
}

// serverHelloBody builds a well-formed ServerHello body with the given
// extension list. Note the ServerHello layout has a single cipher suite and a
// single compression byte where the ClientHello has length-prefixed lists.
func serverHelloBody(exts []tlsExtension) []byte {
	extBytes := marshalExtensions(exts)

	var b bytes.Buffer
	b.Write([]byte{0x03, 0x03})
	b.Write(bytes.Repeat([]byte{0x33}, 32)) // random
	b.WriteByte(32)                         // session id length
	b.Write(bytes.Repeat([]byte{0x44}, 32)) // session id
	b.Write([]byte{0x13, 0x01})             // selected cipher suite
	b.WriteByte(0x00)                       // selected compression
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extBytes)))
	b.Write(extLen[:])
	b.Write(extBytes)
	return b.Bytes()
}

// wrapServerHello wraps a ServerHello body in its handshake header and TLS record.
func wrapServerHello(body []byte) []byte {
	hs := make([]byte, 4+len(body))
	hs[0] = handshakeTypeServerHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = recordTypeHandshake
	binary.BigEndian.PutUint16(rec[1:3], 0x0303)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// testREALITYExt returns a deterministic extension with recognisable halves so
// a swapped PubKey/AuthToken shows up as a value mismatch, not just a length one.
func testREALITYExt() *customtls.REALITYExtension {
	ext := &customtls.REALITYExtension{}
	for i := range ext.PubKey {
		ext.PubKey[i] = byte(i)
	}
	for i := range ext.AuthToken {
		ext.AuthToken[i] = byte(0xA0 + i)
	}
	return ext
}

// realityPaddingExt builds a padding extension (0x0015) whose body starts with
// the marshalled REALITY data and is filled out to totalLen with filler.
func realityPaddingExt(ext *customtls.REALITYExtension, totalLen int) tlsExtension {
	data := ext.Marshal()
	body := make([]byte, totalLen)
	copy(body, data)
	for i := len(data); i < totalLen; i++ {
		body[i] = byte(i % 251)
	}
	return tlsExtension{typ: customtls.PaddingExtensionType, body: body}
}

// clipppedPaddingClientHello builds a ClientHello whose padding extension
// declares the full MinPaddingSize body but carries only the 64 credential
// bytes, with the record and handshake headers sized to what actually arrived.
// This is the shape a middlebox that trims trailing random padding produces.
func clipppedPaddingClientHello(ext *customtls.REALITYExtension) []byte {
	// Extension list: header claiming MinPaddingSize, body of 64 bytes only.
	var exts bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], customtls.PaddingExtensionType)
	binary.BigEndian.PutUint16(hdr[2:4], customtls.MinPaddingSize)
	exts.Write(hdr[:])
	exts.Write(ext.Marshal())

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(bytes.Repeat([]byte{0x11}, 32))
	body.WriteByte(0)           // no session id
	body.Write([]byte{0, 2})    // cipher suites length
	body.Write([]byte{0x13, 1}) // one suite
	body.WriteByte(1)           // compression methods length
	body.WriteByte(0)
	var extLen [2]byte
	// Claims the full extension (4 + 256) though only 4 + 64 follow.
	binary.BigEndian.PutUint16(extLen[:], uint16(4+customtls.MinPaddingSize))
	body.Write(extLen[:])
	body.Write(exts.Bytes())

	return wrapClientHello(body.Bytes())
}

// TestExtractREALITYExtensionFromClientHello covers the happy path plus the
// truncation case the whole scheme depends on: a censor may clip the trailing
// random padding, and the handshake must still recover the 64 auth bytes.
// Failing to would drop every REALITY client behind such a middlebox.
func TestExtractREALITYExtensionFromClientHello(t *testing.T) {
	want := testREALITYExt()

	t.Run("padding extension with full random tail", func(t *testing.T) {
		hello := wrapClientHello(clientHelloBody([]tlsExtension{
			{typ: 0x002b, body: []byte{0x02, 0x03, 0x04}}, // supported_versions, ignored
			realityPaddingExt(want, customtls.MinPaddingSize),
		}))
		got, err := ExtractREALITYExtensionFromClientHello(hello)
		if err != nil {
			t.Fatalf("ExtractREALITYExtensionFromClientHello: %v", err)
		}
		if got.PubKey != want.PubKey {
			t.Errorf("PubKey = %x, want %x", got.PubKey, want.PubKey)
		}
		if got.AuthToken != want.AuthToken {
			t.Errorf("AuthToken = %x, want %x", got.AuthToken, want.AuthToken)
		}
	})

	t.Run("padding body clipped to exactly the auth bytes", func(t *testing.T) {
		// Record and handshake lengths describe what actually arrived, but the
		// extensions-length field and the padding extension's own length still
		// claim the full 256-byte padding: what a middlebox that trimmed the
		// random tail leaves behind. The 64 auth bytes must still come out.
		hello := clipppedPaddingClientHello(want)

		got, err := ExtractREALITYExtensionFromClientHello(hello)
		if err != nil {
			t.Fatalf("clipped padding must still yield the auth data: %v", err)
		}
		if got.PubKey != want.PubKey || got.AuthToken != want.AuthToken {
			t.Errorf("clipped extraction returned the wrong credentials")
		}
		// The cheap peek has to agree with the full parse, or the connection is
		// dispatched to the fake website before ever reaching this code.
		if !DetectREALITYExtension(hello) {
			t.Error("DetectREALITYExtension missed a clipped-but-valid REALITY hello")
		}
	})

	t.Run("padding extension too short to hold credentials", func(t *testing.T) {
		hello := wrapClientHello(clientHelloBody([]tlsExtension{
			{typ: customtls.PaddingExtensionType, body: bytes.Repeat([]byte{0}, 16)},
		}))
		if got, err := ExtractREALITYExtensionFromClientHello(hello); err == nil {
			t.Errorf("got %+v, want an error for a 16-byte padding extension", got)
		}
	})

	t.Run("no padding extension at all", func(t *testing.T) {
		hello := wrapClientHello(clientHelloBody([]tlsExtension{
			{typ: 0x0000, body: []byte{0x00, 0x03, 0x00, 0x00, 0x00}},
		}))
		if _, err := ExtractREALITYExtensionFromClientHello(hello); err == nil {
			t.Error("a plain ClientHello must not be reported as REALITY")
		}
	})
}

// TestExtractREALITYExtensionRejectsWrongMessages pins the type checks. A
// ServerHello or a non-handshake record reaching the REALITY path would mean
// the dispatcher misrouted the connection.
func TestExtractREALITYExtensionRejectsWrongMessages(t *testing.T) {
	ext := testREALITYExt()

	// Application-data record instead of handshake.
	appData := wrapClientHello(clientHelloBody(nil))
	appData[0] = 0x17
	if _, err := ExtractREALITYExtensionFromClientHello(appData); err == nil {
		t.Error("non-handshake record accepted")
	}

	// Handshake record carrying a ServerHello.
	sh := wrapServerHello(serverHelloBody([]tlsExtension{realityPaddingExt(ext, 128)}))
	if _, err := ExtractREALITYExtensionFromClientHello(sh); err == nil {
		t.Error("ServerHello accepted as a ClientHello")
	}
}

// TestExtractREALITYExtensionMalformedNoPanic is the DoS guard: hostile or
// truncated bytes from the network must produce an error, never an
// index-out-of-range that takes the listener down.
func TestExtractREALITYExtensionMalformedNoPanic(t *testing.T) {
	bodies := [][]byte{
		{},
		make([]byte, 10),
		make([]byte, 34),
		append(make([]byte, 34), 0xff),
		append(make([]byte, 35), 0xff, 0xff),
		buildOverrunExtensions(),
	}
	for i, body := range bodies {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: panicked: %v", i, r)
				}
			}()
			hello := wrapClientHello(body)
			_, _ = ExtractREALITYExtensionFromClientHello(hello)
			_ = DetectREALITYExtension(hello)
		}()
	}

	// Raw prefixes of a real ClientHello, byte by byte: every truncation point
	// has to be handled.
	full := wrapClientHello(clientHelloBody([]tlsExtension{realityPaddingExt(testREALITYExt(), 300)}))
	for n := 0; n < len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("prefix of %d bytes panicked: %v", n, r)
				}
			}()
			_, _ = ExtractREALITYExtensionFromClientHello(full[:n])
			_ = DetectREALITYExtension(full[:n])
			_, _ = RemoveREALITYExtension(full[:n])
			_, _ = ExtractSNI(full[:n])
		}()
	}
}

// TestDetectREALITYExtension covers the cheap pre-dispatch peek. A false
// negative sends a real client to the fake website; a false positive on plain
// TLS breaks the camouflage the whole design rests on.
func TestDetectREALITYExtension(t *testing.T) {
	ext := testREALITYExt()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "REALITY ClientHello",
			data: wrapClientHello(clientHelloBody([]tlsExtension{realityPaddingExt(ext, customtls.MinPaddingSize)})),
			want: true,
		},
		{
			name: "REALITY padding after other extensions",
			data: wrapClientHello(clientHelloBody([]tlsExtension{
				{typ: 0x0000, body: []byte{0x00, 0x03, 0x00, 0x00, 0x00}},
				{typ: 0x002b, body: []byte{0x02, 0x03, 0x04}},
				realityPaddingExt(ext, 128),
			})),
			want: true,
		},
		{
			name: "plain ClientHello with SNI only",
			data: wrapClientHello(clientHelloBody([]tlsExtension{
				{typ: 0x0000, body: []byte{0x00, 0x03, 0x00, 0x00, 0x00}},
			})),
			want: false,
		},
		{
			name: "padding extension too small for credentials",
			data: wrapClientHello(clientHelloBody([]tlsExtension{
				{typ: customtls.PaddingExtensionType, body: bytes.Repeat([]byte{0}, 32)},
			})),
			want: false,
		},
		{name: "empty input", data: nil, want: false},
		{name: "short input", data: []byte{0x16, 0x03}, want: false},
		{name: "not a TLS record", data: bytes.Repeat([]byte{0x41}, 200), want: false},
		{
			name: "handshake record that is not a ClientHello",
			data: wrapServerHello(serverHelloBody([]tlsExtension{realityPaddingExt(ext, 128)})),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectREALITYExtension(tt.data); got != tt.want {
				t.Errorf("DetectREALITYExtension = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRemoveREALITYExtension covers the forwarding path: before the ClientHello
// is relayed to the real camouflage host, the padding extension has to go. A
// leftover padding extension is exactly the fingerprint an observer would use
// to tell a REALITY client from a browser.
func TestRemoveREALITYExtension(t *testing.T) {
	ext := testREALITYExt()
	sni := tlsExtension{typ: 0x0000, body: []byte{0x00, 0x0c, 0x00, 0x00, 0x09,
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'}}
	versions := tlsExtension{typ: 0x002b, body: []byte{0x02, 0x03, 0x04}}

	hello := wrapClientHello(clientHelloBody([]tlsExtension{
		sni,
		realityPaddingExt(ext, customtls.MinPaddingSize),
		versions,
	}))

	stripped, err := RemoveREALITYExtension(hello)
	if err != nil {
		t.Fatalf("RemoveREALITYExtension: %v", err)
	}

	if DetectREALITYExtension(stripped) {
		t.Error("stripped ClientHello still detects as REALITY")
	}
	if _, err := ExtractREALITYExtensionFromClientHello(stripped); err == nil {
		t.Error("credentials still extractable from the stripped ClientHello")
	}
	if bytes.Contains(stripped, ext.Marshal()) {
		t.Error("the raw credential bytes are still on the wire")
	}

	// The surviving extensions must be intact, or the camouflage host sees a
	// mangled hello and aborts.
	host, err := ExtractSNI(stripped)
	if err != nil {
		t.Fatalf("ExtractSNI on the stripped hello: %v", err)
	}
	if host != "localhost" {
		t.Errorf("SNI = %q, want localhost", host)
	}
	if !bytes.Contains(stripped, versions.body) {
		t.Error("supported_versions extension was dropped along with the padding")
	}

	// The rebuilt record must be self-consistent: record length, handshake
	// length and actual byte count all agree, or the peer stalls waiting for
	// bytes that never arrive.
	rec, err := ParseTLSRecord(stripped)
	if err != nil {
		t.Fatalf("ParseTLSRecord on the stripped hello: %v", err)
	}
	if int(rec.Length) != len(stripped)-5 {
		t.Errorf("record length %d does not match the %d bytes that follow", rec.Length, len(stripped)-5)
	}
	msg, err := ParseHandshakeMessage(rec.Payload)
	if err != nil {
		t.Fatalf("ParseHandshakeMessage on the stripped hello: %v", err)
	}
	if int(msg.Length) != len(rec.Payload)-4 {
		t.Errorf("handshake length %d does not match the %d bytes that follow", msg.Length, len(rec.Payload)-4)
	}
	if len(stripped) >= len(hello) {
		t.Errorf("stripped hello is %d bytes, not shorter than the original %d", len(stripped), len(hello))
	}

	// Removing from a hello that never had the extension is a no-op, not an error.
	plain := wrapClientHello(clientHelloBody([]tlsExtension{sni}))
	again, err := RemoveREALITYExtension(plain)
	if err != nil {
		t.Fatalf("RemoveREALITYExtension on a plain hello: %v", err)
	}
	if !bytes.Equal(again, plain) {
		t.Errorf("a hello with no padding extension was rewritten: %x vs %x", again, plain)
	}
}

// TestRemoveExtensionByType covers the extension-list filter directly,
// including the list shapes RemoveREALITYExtension itself cannot reach.
func TestRemoveExtensionByType(t *testing.T) {
	a := tlsExtension{typ: 0x0001, body: []byte{1, 2, 3}}
	b := tlsExtension{typ: 0x0015, body: []byte{4, 5}}
	c := tlsExtension{typ: 0x0002, body: nil}

	tests := []struct {
		name  string
		input []tlsExtension
		strip uint16
		want  []tlsExtension
	}{
		{"empty list", nil, 0x0015, nil},
		{"nothing matches", []tlsExtension{a, c}, 0x0015, []tlsExtension{a, c}},
		{"strip middle", []tlsExtension{a, b, c}, 0x0015, []tlsExtension{a, c}},
		{"strip first", []tlsExtension{b, a}, 0x0015, []tlsExtension{a}},
		{"strip last", []tlsExtension{a, b}, 0x0015, []tlsExtension{a}},
		{"strip only", []tlsExtension{b}, 0x0015, nil},
		{"strip duplicates", []tlsExtension{b, a, b}, 0x0015, []tlsExtension{a}},
		{"zero-length extension survives", []tlsExtension{c}, 0x0015, []tlsExtension{c}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeExtensionByType(marshalExtensions(tt.input), tt.strip)
			want := marshalExtensions(tt.want)
			if !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

// TestInjectREALITYExtension covers the server's answer: the credentials go
// into a padding extension appended to the ServerHello, and the rebuilt record
// has to stay well-formed or the client cannot complete the handshake.
func TestInjectREALITYExtension(t *testing.T) {
	ext := testREALITYExt()
	original := wrapServerHello(serverHelloBody([]tlsExtension{
		{typ: 0x002b, body: []byte{0x03, 0x04}},
	}))

	injected, err := InjectREALITYExtension(original, ext)
	if err != nil {
		t.Fatalf("InjectREALITYExtension: %v", err)
	}

	if !bytes.Contains(injected, ext.Marshal()) {
		t.Fatal("the marshalled credentials are not present in the injected ServerHello")
	}
	if len(injected) <= len(original) {
		t.Errorf("injected hello is %d bytes, not longer than the original %d", len(injected), len(original))
	}

	// Record and handshake lengths must describe the actual bytes.
	rec, err := ParseTLSRecord(injected)
	if err != nil {
		t.Fatalf("ParseTLSRecord: %v", err)
	}
	if int(rec.Length) != len(injected)-5 {
		t.Errorf("record length %d does not match the %d bytes that follow", rec.Length, len(injected)-5)
	}
	msg, err := ParseHandshakeMessage(rec.Payload)
	if err != nil {
		t.Fatalf("ParseHandshakeMessage: %v", err)
	}
	if msg.Type != handshakeTypeServerHello {
		t.Errorf("handshake type = 0x%02x, want ServerHello", msg.Type)
	}
	if int(msg.Length) != len(rec.Payload)-4 {
		t.Errorf("handshake length %d does not match the %d bytes that follow", msg.Length, len(rec.Payload)-4)
	}

	// The extensions-length field must have grown by exactly the appended
	// extension, or the client stops parsing before reaching the padding.
	origExtLen := binary.BigEndian.Uint16(original[5+4+34+1+32+2+1:])
	newExtLen := binary.BigEndian.Uint16(injected[5+4+34+1+32+2+1:])
	if int(newExtLen) <= int(origExtLen) {
		t.Errorf("extensions length did not grow: %d -> %d", origExtLen, newExtLen)
	}
	if int(newExtLen)-int(origExtLen) != 4+customtls.MinPaddingSize {
		t.Errorf("extensions length grew by %d, want %d", int(newExtLen)-int(origExtLen), 4+customtls.MinPaddingSize)
	}

	// Wrong message types must be refused rather than corrupted in place.
	clientHello := wrapClientHello(clientHelloBody(nil))
	if _, err := InjectREALITYExtension(clientHello, ext); err == nil {
		t.Error("InjectREALITYExtension accepted a ClientHello")
	}
	if _, err := InjectREALITYExtension([]byte{0x16, 0x03}, ext); err == nil {
		t.Error("InjectREALITYExtension accepted a truncated record")
	}
}

// TestReadTLSRecord covers the framed read used before any parsing. A reader
// that returns the header but stops short must error rather than hand a
// partial record to the parsers.
func TestReadTLSRecord(t *testing.T) {
	full := wrapClientHello(clientHelloBody([]tlsExtension{
		{typ: 0x0000, body: []byte{0x00, 0x03, 0x00, 0x00, 0x00}},
	}))

	t.Run("complete record", func(t *testing.T) {
		got, err := ReadTLSRecord(bytes.NewReader(full))
		if err != nil {
			t.Fatalf("ReadTLSRecord: %v", err)
		}
		if !bytes.Equal(got, full) {
			t.Errorf("read %d bytes, want the whole %d-byte record", len(got), len(full))
		}
	})

	t.Run("trailing bytes are left in the stream", func(t *testing.T) {
		stream := bytes.NewReader(append(append([]byte{}, full...), 'X', 'Y'))
		got, err := ReadTLSRecord(stream)
		if err != nil {
			t.Fatalf("ReadTLSRecord: %v", err)
		}
		if len(got) != len(full) {
			t.Fatalf("read %d bytes, want exactly one %d-byte record", len(got), len(full))
		}
		rest, _ := io.ReadAll(stream)
		if !bytes.Equal(rest, []byte("XY")) {
			t.Errorf("leftover = %q, want %q (the next record must not be consumed)", rest, "XY")
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		if _, err := ReadTLSRecord(bytes.NewReader(full[:3])); err == nil {
			t.Error("ReadTLSRecord accepted a 3-byte header")
		}
	})

	t.Run("truncated payload", func(t *testing.T) {
		if _, err := ReadTLSRecord(bytes.NewReader(full[:len(full)-1])); err == nil {
			t.Error("ReadTLSRecord returned a record whose payload was short")
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		if _, err := ReadTLSRecord(bytes.NewReader(nil)); err == nil {
			t.Error("ReadTLSRecord accepted an empty stream")
		}
	})
}

// TestMarshalRoundTrip pins the serialisers against their parsers: a record or
// handshake message that does not survive a round trip would desynchronise the
// forwarded stream to the camouflage host.
func TestMarshalRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 300)

	msg := &HandshakeMessage{Type: handshakeTypeClientHello, Length: uint32(len(payload)), Payload: payload}
	parsedMsg, err := ParseHandshakeMessage(marshalHandshakeMessage(msg))
	if err != nil {
		t.Fatalf("ParseHandshakeMessage: %v", err)
	}
	if parsedMsg.Type != msg.Type || parsedMsg.Length != msg.Length || !bytes.Equal(parsedMsg.Payload, payload) {
		t.Errorf("handshake round trip mismatch: %+v", parsedMsg)
	}

	rec := &TLSRecord{Type: recordTypeHandshake, Version: 0x0303, Length: uint16(len(payload)), Payload: payload}
	parsedRec, err := ParseTLSRecord(marshalTLSRecord(rec))
	if err != nil {
		t.Fatalf("ParseTLSRecord: %v", err)
	}
	if parsedRec.Type != rec.Type || parsedRec.Version != rec.Version || !bytes.Equal(parsedRec.Payload, payload) {
		t.Errorf("record round trip mismatch: %+v", parsedRec)
	}

	// The 24-bit handshake length field must survive values above 16 bits.
	big := &HandshakeMessage{Type: 0x01, Length: 0x010203}
	marshalled := marshalHandshakeMessage(big)
	if marshalled[1] != 0x01 || marshalled[2] != 0x02 || marshalled[3] != 0x03 {
		t.Errorf("24-bit length encoded as %x, want 010203", marshalled[1:4])
	}
}

// TestFindREALITYExtensionDirect exercises the extension walker on lists that a
// full ClientHello cannot easily express, including the truncation break.
func TestFindREALITYExtensionDirect(t *testing.T) {
	ext := testREALITYExt()

	t.Run("empty list", func(t *testing.T) {
		if _, err := findREALITYExtension(nil); err == nil {
			t.Error("empty extension list reported a REALITY extension")
		}
	})

	t.Run("truncated before the padding extension", func(t *testing.T) {
		exts := marshalExtensions([]tlsExtension{
			{typ: 0x002b, body: bytes.Repeat([]byte{0}, 40)},
			realityPaddingExt(ext, 128),
		})
		// Cut inside the first extension's body: the walker cannot reach the
		// padding and must say so rather than read past the slice.
		if _, err := findREALITYExtension(exts[:20]); err == nil {
			t.Error("truncated extension list reported a REALITY extension")
		}
	})

	t.Run("padding declared long but body available", func(t *testing.T) {
		exts := marshalExtensions([]tlsExtension{realityPaddingExt(ext, 512)})
		// Keep 4 header bytes plus exactly the credentials.
		clipped := exts[:4+customtls.REALITYExtensionLength]
		got, err := findREALITYExtension(clipped)
		if err != nil {
			t.Fatalf("clipped padding body: %v", err)
		}
		if got.PubKey != ext.PubKey || got.AuthToken != ext.AuthToken {
			t.Error("clipped padding body yielded the wrong credentials")
		}
	})

	t.Run("padding shorter than the credentials", func(t *testing.T) {
		exts := marshalExtensions([]tlsExtension{
			{typ: customtls.PaddingExtensionType, body: bytes.Repeat([]byte{0}, customtls.REALITYExtensionLength-1)},
		})
		if _, err := findREALITYExtension(exts); err == nil {
			t.Error("a padding extension one byte short of the credentials was accepted")
		}
	})
}
