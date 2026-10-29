package strategy

import "strings"

// Camouflage-only classification.
//
// Some transports dial with tls.Config.InsecureSkipVerify=true (or no TLS at
// all) and never make the server prove its identity to the client in a way that
// survives an active man-in-the-middle. For those, the outer TLS is the only
// confidentiality layer and it is unauthenticated: an attacker who can terminate
// the connection in the path between client and server can pose as the exit,
// answer with whatever byte or status the client expects, and read everything
// the client tunnels into it. They defeat blocking; they do not defend against a
// targeted active MITM. REALITY B1 (-reality-b1) is the transport that does.
//
// This map is the single source of truth. Keys are base strategy IDs; a variant
// suffix (morph_<profile>, geneva_<country>, confusion_<n>) is matched on its
// base. The value is the evidence: what the server actually sends back, and why
// it proves nothing replay-proof. See docs/security.md, "The ordinary TLS
// transports", for the full write-up.
//
// Transports NOT listed here authenticate the server with a secret-keyed proof
// bound to a fresh per-connection value, so a peer without the secret cannot
// impersonate the server and a captured proof cannot be replayed:
//   - reality / seqovl: HMAC(secret, clientPubKey‖"reality-server-ack") in the
//     ServerHello padding, verified before any data (reality.go VerifyServerAuth,
//     tls/reality_extension.go:157).
//   - reality_b1: real TLS 1.3 with an HMAC in VerifyPeerCertificate plus an
//     exporter binding (docs/security.md, "REALITY B1").
//   - antiprobe: HMAC(secret, TLS session exporter) (antiprobe.go verifyServerAuth).
//   - quic / quic_salamander: server marker keyed to the secret and the client's
//     fresh nonce (quic.go, quicServerMarker).
//   - ssh_camouflage: server auth token over the SSH session id in a distinct
//     direction context (ssh_camouflage.go VerifySSHAuthToken).
//   - confusion_* / state_exhaustion: server marker keyed to (secret, fresh
//     nonce) plus a ChaCha20-Poly1305 data layer (confusion_crypto.go).
//   - icmp_tunnel: ChaCha20-Poly1305 with per-session keys from the secret, so
//     only the secret holder can produce packets the client will open
//     (icmp_tunnel.go).
var camouflageOnlyIDs = map[string]string{
	"morph":            "server replies with a single 0x00 ack that any peer can send (morph.go)",
	"websocket_padded": "server replies with an HTTP 101 and proves nothing (websocket_padded.go)",
	"geneva":           "rides WebSocket-padded; server replies with an HTTP 101 only (geneva_strategy.go)",
	"http_polling":     "server replies with a plain \"OK\" and proves nothing (http_polling.go)",
	"mesh_relay":       "relay answers a 1-byte 0x01; no keyed relay-to-client proof (mesh.go authenticateRelay)",
	"imap_camouflage":  "SASL CRAM-MD5 authenticates client-to-server only; server returns a plain tagged OK (imap_camouflage.go)",
	"http2_stego":      "server ack is HMAC(secret, server-chosen nonce), not bound to the TLS session, so an on-path attacker who captured one ack can replay it (stego.go verifyServerAckHeaders)",
}

// camouflageOnlyReason reports whether the strategy id is camouflage-only (no
// server authentication that survives an active MITM) and, if so, the one-line
// evidence. It matches the full id first, then the base before any "_variant"
// suffix.
func camouflageOnlyReason(id string) (string, bool) {
	if reason, ok := camouflageOnlyIDs[id]; ok {
		return reason, true
	}
	if base, _, found := strings.Cut(id, "_"); found {
		if reason, ok := camouflageOnlyIDs[base]; ok {
			return reason, true
		}
	}
	return "", false
}

// IsCamouflageOnly reports whether the strategy id names a transport that does
// not authenticate the server to the client. See camouflageOnlyIDs.
func IsCamouflageOnly(id string) bool {
	_, ok := camouflageOnlyReason(id)
	return ok
}
