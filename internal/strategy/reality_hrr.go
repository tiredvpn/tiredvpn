package strategy

import (
	"crypto/subtle"
	"errors"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// helloRetryRequestRandom is SHA-256("HelloRetryRequest"), the sentinel a TLS
// 1.3 server puts in ServerHello.random to signal a retry (RFC 8446 §4.1.3).
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// errHelloRetryRequest reports that the peer asked us to retry the handshake.
// It is a distinct error so a probe is distinguishable in logs and metrics from
// an ordinary malformed ServerHello — previously an injected HRR surfaced as
// "reality extension not found", indistinguishable from noise.
var errHelloRetryRequest = errors.New("reality: peer sent HelloRetryRequest (probe or real donor), aborting")

// isHelloRetryRequest reports whether a complete TLS handshake record holds a
// HelloRetryRequest.
//
// Layout: [record hdr:5][hs type:1][hs len:3][legacy_version:2][random:32]
// so ServerHello.random starts at offset 11.
func isHelloRetryRequest(record []byte) bool {
	const randomOffset = 5 + 4 + 2
	if len(record) < randomOffset+32 {
		return false
	}
	if record[0] != 0x16 || record[5] != 0x02 { // handshake record, ServerHello
		return false
	}
	return subtle.ConstantTimeCompare(record[randomOffset:randomOffset+32], helloRetryRequestRandom[:]) == 1
}

// handleHelloRetryRequest reacts to a HelloRetryRequest we cannot satisfy.
//
// What we do: send a plaintext fatal illegal_parameter alert, then close. That
// is what a real TLS 1.3 client does when a HRR asks for something outside its
// supported_groups, so a naive probe that injects a HRR for a group we do not
// advertise sees browser-shaped behaviour instead of a bare RST.
//
// What we do NOT do: retry. A correct response means building a second
// ClientHello with a fresh key share in the requested group, echoing the HRR
// cookie, and — per RFC 9849 §6.2.1 — copying the GREASE ECH extension
// byte-for-byte, because a genuine ECH client instead zeroes `enc` and re-encrypts
// the payload. That distinction is exactly what a censor able to trigger HRR
// uses to separate GREASE ECH from real ECH, and it matters for us now that the
// default Firefox profile carries GREASE ECH.
//
// Doing this properly means a partial TLS 1.3 client state machine on top of a
// hand-rolled handshake, and that whole path is deleted by Phase 2 (driving
// uTLS through a real uconn.Handshake(), which handles HRR upstream for free).
// So this stays a known, logged gap rather than throwaway code: an in-path
// probe that injects a well-formed HRR for a group we do advertise still sees
// us abort where a browser would continue.
func (r *REALITYStrategy) handleHelloRetryRequest(conn net.Conn, dest string) {
	log.Warn("REALITY: HelloRetryRequest from %s — cannot retry, aborting handshake "+
		"(likely an in-path probe; see reality_hrr.go)", dest)

	// alert record: content type 0x15, TLS 1.2 legacy version, fatal(2),
	// illegal_parameter(47).
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2F}
	if _, err := conn.Write(alert); err != nil {
		log.Debug("REALITY: HRR alert write failed: %v", err)
	}
}
