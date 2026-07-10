package server

import (
	"crypto/hmac"
	"crypto/sha256"
)

// seqovlDecoySalt is the HMAC domain separator for the seqovl decoy marker.
// It must match the client (internal/strategy/seqovl.go) exactly.
const seqovlDecoySalt = "tiredvpn-seqovl-decoy-v1"

const (
	seqovlNonceLen        = 16
	seqovlMarkerLen       = 32
	seqovlMinDecoyPayload = seqovlNonceLen + seqovlMarkerLen // 48
	// seqovlMaxDecoys bounds how many leading decoy records the server will drop
	// before a real ClientHello, so a client cannot pin the read loop forever.
	seqovlMaxDecoys = 4
)

// seqovlMarker computes HMAC-SHA256(secret, salt||nonce)[:32], matching the
// client-side marker computation.
func seqovlMarker(secret, nonce []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(seqovlDecoySalt))
	mac.Write(nonce)
	return mac.Sum(nil)[:seqovlMarkerLen]
}

// isSeqovlDecoy reports whether peekBuf is a seqovl decoy record authenticated
// under one of the server's known secrets.
//
// The check is additive and cheap for baseline traffic: a genuine ClientHello
// starts its handshake body with 0x01, which the fast gate rejects before any
// HMAC is computed, so REALITY / Geneva / Morph handshakes are never touched.
// Only records whose first payload byte is not a ClientHello type (i.e. traffic
// that would otherwise be dropped as unknown) reach the constant-time marker
// comparison.
func isSeqovlDecoy(peekBuf []byte, srvCtx *serverContext) bool {
	if len(peekBuf) < 5 || peekBuf[0] != recordTypeHandshake {
		return false
	}
	recordLen := int(peekBuf[3])<<8 | int(peekBuf[4])
	if recordLen < seqovlMinDecoyPayload || 5+recordLen > len(peekBuf) {
		return false
	}
	payload := peekBuf[5 : 5+recordLen]

	// Fast gate: real ClientHello handshake bodies begin with 0x01. Decoys force
	// payload[0] != 0x01, so no baseline handshake reaches the HMAC comparison.
	if payload[0] == handshakeTypeClientHello {
		return false
	}

	nonce := payload[0:seqovlNonceLen]
	mac := payload[seqovlNonceLen : seqovlNonceLen+seqovlMarkerLen]

	// Global secret first (cheapest, most common deployment).
	if len(srvCtx.cfg.Secret) > 0 && hmac.Equal(mac, seqovlMarker(srvCtx.cfg.Secret, nonce)) {
		return true
	}

	// Then per-client secrets from the registry — the same secret set REALITY
	// auth already walks per connection.
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			if hmac.Equal(mac, seqovlMarker([]byte(client.Secret), nonce)) {
				return true
			}
		}
	}

	return false
}
