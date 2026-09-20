package strategy

import (
	"bytes"
	"testing"
)

// F1 (S22): the QUIC auth token must be bound to the connection's TLS session
// exporter, so a token captured on one QUIC connection is rejected on another.
// quicAuthToken is the derivation both QUICConn.generateAuthToken (client) and
// QUICServerConn.VerifyClient (server) use. Predelivered to the pre-binding code
// (drop the h.Write(ekm) in quicAuthToken) this goes green-to-red.
func TestQUICAuthTokenBindsToSession(t *testing.T) {
	t.Parallel()
	secret := []byte("quic-bind-secret")
	ekmA := []byte("quic-exporter-A-0123456789abcdef0")
	ekmB := []byte("quic-exporter-B-0123456789abcdef0")

	tokA := quicAuthToken(secret, ekmA, 0)

	if !bytes.Equal(tokA, quicAuthToken(secret, ekmA, 0)) {
		t.Fatal("quic token is not reproducible for a fixed session and bucket")
	}
	if bytes.Equal(tokA, quicAuthToken(secret, ekmB, 0)) {
		t.Fatal("quic token is identical across two session exporters; not session-bound")
	}
}
