package strategy

import (
	"crypto/rand"
	"io"
	"testing"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// TestS6TamperedV2ConfirmationRefused covers the requireDataV2 default. An
// on-path attacker who flips bytes of the v2 confirmation (it rides in the
// cleartext ServerHello padding) must not be able to force the malleable v1
// keystream. With requireDataV2 set (the shipped default) the flip is an error;
// the broken-default subtest (requireDataV2 false) is the red control showing
// the silent downgrade the fix removes.
func TestS6TamperedV2ConfirmationRefused(t *testing.T) {
	t.Parallel()

	secret := []byte("shared-secret")

	clientPriv, clientPub, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, _, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var clientSalt, serverSalt [32]byte
	if _, err := rand.Read(clientSalt[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(serverSalt[:]); err != nil {
		t.Fatal(err)
	}

	ext, err := customtls.NewServerREALITYExtensionDataV2(secret, serverPriv, clientPub, clientSalt, serverSalt)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper: flip the last byte of the confirmation an active middlebox can reach.
	ext.Extra[len(ext.Extra)-1] ^= 0xff

	// Shipped default (requireDataV2 true): tampering is a hard error.
	secure := &REALITYStrategy{secret: secret, requireDataV2: true}
	if _, err := secure.wrapDataLayer(writeOnlyConn{Writer: io.Discard}, ext, clientPriv, clientPub, clientSalt, secret); err == nil {
		t.Fatal("tampered v2 confirmation was accepted; a MITM could strip it and force the malleable v1 stream")
	}

	// Pre-fix default (requireDataV2 false): same tamper silently downgrades to
	// the v1 keystream conn with no error. This is the control for rule 1.
	legacy := &REALITYStrategy{secret: secret}
	c, err := legacy.wrapDataLayer(writeOnlyConn{Writer: io.Discard}, ext, clientPriv, clientPub, clientSalt, secret)
	if err != nil {
		t.Fatalf("legacy default errored unexpectedly: %v", err)
	}
	if _, ok := c.(*realityDataConn); !ok {
		t.Fatalf("expected the pre-fix default to silently downgrade to *realityDataConn, got %T", c)
	}
}
