package server

import (
	"encoding/binary"
	"testing"
)

// wrapClientHello wraps a raw ClientHello body (the bytes after the 4-byte
// handshake header) into a complete TLS handshake record.
func wrapClientHello(body []byte) []byte {
	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // ClientHello
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

// TestExtractSNI_MalformedNoPanic verifies that truncated or hostile
// ClientHello bodies return an error instead of panicking with
// index-out-of-range (remote DoS hardening).
func TestExtractSNI_MalformedNoPanic(t *testing.T) {
	bodies := [][]byte{
		{},                                   // empty
		make([]byte, 10),                     // shorter than 34-byte version+random
		make([]byte, 34),                     // ends exactly at session id length
		append(make([]byte, 34), 0xff),       // sessionIDLen=255 but nothing follows
		append(make([]byte, 35), 0xff, 0xff), // cipher suites length overruns
		buildOverrunExtensions(),             // extensions length overruns payload
	}
	for i, body := range bodies {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: ExtractSNI panicked: %v", i, r)
				}
			}()
			hello := wrapClientHello(body)
			_, _ = ExtractSNI(hello)
			_, _ = RemoveREALITYExtension(hello)
		}()
	}
}

// buildOverrunExtensions builds a body whose extensions-length field claims
// far more bytes than are actually present.
func buildOverrunExtensions() []byte {
	body := make([]byte, 0, 64)
	body = append(body, make([]byte, 34)...) // version + random
	body = append(body, 0x00)                // sessionIDLen = 0
	body = append(body, 0x00, 0x00)          // cipherSuitesLen = 0
	body = append(body, 0x00)                // compressionMethodsLen = 0
	body = append(body, 0xff, 0xff)          // extensionsLen = 65535 (overrun)
	return body
}
