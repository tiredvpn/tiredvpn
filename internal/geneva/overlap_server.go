package geneva

import (
	"crypto/subtle"
	"errors"
)

// The server-side counterpart to the packet-level seqovl overlap lives here.
// OverlapServerDropper (defined per platform in overlap_server_linux.go /
// overlap_server_other.go) attaches an *input* NFQUEUE hook on the relay,
// recognises a seqovl fake segment by verifying the self-describing marker at the
// start of the TCP payload, and DROPs it before kernel reassembly so the
// application receives only the real ClientHello.
//
// Why the drop can only happen at the packet layer, never in the application:
// the fake segment's sequence numbers are strictly below the server's rcv_nxt
// (OverlapPrimitive backs the fake up by OverlapLen >= OverlapMarkerLen). The
// server kernel discards everything below rcv_nxt before any read() sees it, so
// the marker never reaches an application read - including the app-framing decoy
// path in internal/server/seqovl.go, which handles the *level-B* record, a
// different mechanism entirely. The only place a fake segment is observable by
// its marker is on ingress, before reassembly, which is exactly what an input
// NFQUEUE delivers. This is reachable from userspace (NFQUEUE is a userspace
// mechanism, the mirror image of the client's OUTPUT injector), so the server
// verification is achievable - just not at the app layer.
//
// The dropper is only *required* for the aggressive overlap-into-ClientHello
// geometry (OverlapPrimitive.FakeLen > OverlapLen), which delivers junk into the
// real stream. With the default safe geometry (FakeLen == OverlapLen) the fake
// stays entirely below rcv_nxt and the kernel discards it unaided, so the dropper
// is not needed and the relay avoids an always-on input NFQUEUE. Because that
// NFQUEUE spans matched inbound traffic on memory-constrained relays, callers
// must gate it behind an explicit flag and a narrow iptables match (source
// port / connection mark), never the whole ingress.

// ErrOverlapDropperUnimplemented is returned by Start on platforms without
// NFQUEUE support (everything but Linux).
var ErrOverlapDropperUnimplemented = errors.New("geneva: seqovl server-side overlap dropper requires Linux NFQUEUE")

// OverlapMarkerVerifier verifies a self-describing overlap marker laid out as
// [nonce:NonceLen][MAC] at the start of a fake segment's payload. It stays
// agnostic of the HMAC salt and secret: the caller supplies Mint, the same
// function the client uses to derive the full OverlapMarkerLen-byte marker from a
// nonce (e.g. strategy.seqovlPacketMarker bound to one secret). Matches
// recomputes the expected marker from the embedded nonce and compares in constant
// time, so a censor cannot forge or recognise a fake without the secret.
type OverlapMarkerVerifier struct {
	// NonceLen is the length of the nonce prefix embedded in the marker.
	NonceLen int
	// Mint returns the full OverlapMarkerLen-byte marker for a given nonce.
	Mint func(nonce []byte) []byte
}

// Matches reports whether payload begins with an authentic marker under this
// verifier. It reads only the fixed OverlapMarkerLen-byte prefix, so a genuine
// ClientHello (or any payload whose nonce does not reproduce the MAC) is rejected.
func (v OverlapMarkerVerifier) Matches(payload []byte) bool {
	if v.Mint == nil || v.NonceLen <= 0 || v.NonceLen >= OverlapMarkerLen {
		return false
	}
	if len(payload) < OverlapMarkerLen {
		return false
	}
	nonce := payload[:v.NonceLen]
	expect := v.Mint(nonce)
	if len(expect) != OverlapMarkerLen {
		return false
	}
	return subtle.ConstantTimeCompare(payload[:OverlapMarkerLen], expect) == 1
}

// AnyOverlapVerifier folds several per-secret verifiers into one Verify closure:
// a payload is a fake if any verifier matches it. Used by a relay that serves
// more than one client secret. It walks every verifier (no early return on the
// first mismatch) so the number of secrets does not leak through timing.
func AnyOverlapVerifier(verifiers ...OverlapMarkerVerifier) func(payload []byte) bool {
	return func(payload []byte) bool {
		var hit bool
		for _, v := range verifiers {
			if v.Matches(payload) {
				hit = true
			}
		}
		return hit
	}
}

// overlapPacketTCPPayload returns the TCP payload of an IPv4 TCP packet, or nil
// if the packet is not a well-formed IPv4 TCP segment with a payload.
func overlapPacketTCPPayload(packet []byte) []byte {
	if len(packet) < 20 {
		return nil
	}
	if packet[0]>>4 != 4 { // IPv4 only; the client injector is IPv4-only too
		return nil
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if ipHeaderLen < 20 || len(packet) < ipHeaderLen+20 {
		return nil
	}
	if packet[9] != 6 { // TCP
		return nil
	}
	tcpStart := ipHeaderLen
	tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
	if tcpHeaderLen < 20 {
		return nil
	}
	payloadStart := tcpStart + tcpHeaderLen
	if len(packet) <= payloadStart {
		return nil
	}
	return packet[payloadStart:]
}

// overlapPacketIsFake reports whether a raw IPv4 TCP packet carries a seqovl fake
// segment authentic under verify. This is the pure decision the input NFQUEUE
// hook makes per packet: true => NF_DROP, false => NF_ACCEPT. Kept
// platform-independent so it is unit-testable without a live NFQUEUE.
func overlapPacketIsFake(packet []byte, verify func(payload []byte) bool) bool {
	if verify == nil {
		return false
	}
	payload := overlapPacketTCPPayload(packet)
	if payload == nil {
		return false
	}
	return verify(payload)
}
