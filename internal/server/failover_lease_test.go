package server

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// realityIdentityFor runs the REALITY server's own authentication for a client
// holding secret and returns the identity the session gets - the path a REALITY
// handshake takes, from the auth token to realityClientIdentity.
func realityIdentityFor(t *testing.T, srvCtx *serverContext, secret []byte) clientIdentity {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	ext, err := customtls.NewClientREALITYExtension(secret, priv)
	if err != nil {
		t.Fatalf("NewClientREALITYExtension: %v", err)
	}
	_, id, _, ok := authenticateREALITYClient(srvCtx, ext, log.WithPrefix("test"))
	if !ok {
		t.Fatal("REALITY auth failed for a known secret")
	}
	return id
}

// TestOneClientKeepsItsLeaseAcrossTransports is N2 of the PR #126 acceptance
// run. The tunnel address is sticky per lease key, and the key was the
// identity as each transport spells it: "reality:<hmac>" for REALITY, "global"
// for Geneva/WS/confusion/SSH/IMAP, "polling:global" for HTTP polling. A client
// moving its live tunnel from Geneva to REALITY (the D3 upgrade) came back as
// somebody else - "Requested IP 10.8.1.2 already leased to client reality:...;
// will be auto-allocated a different IP" - and the move was thrown away every
// time.
//
// One secret, one client, one origin: every transport must land on one lease.
func TestOneClientKeepsItsLeaseAcrossTransports(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	perClient := []byte("a-registry-client-secret-32bytes")

	reg := NewClientRegistry(nil)
	c1 := &ClientConfig{ID: "c1", Name: "laptop", Secret: string(perClient), Enabled: true}
	reg.byID[c1.ID] = c1
	reg.bySecret[c1.Secret] = c1
	srvCtx := &serverContext{cfg: &Config{Secret: global}, registry: reg}

	const origin = "192.0.2.170"
	cases := []struct {
		name   string
		secret []byte
		others []clientIdentity // what the other transports resolve for it
	}{
		{"global secret", global, []clientIdentity{
			sharedIdentity(globalClientID),                     // Geneva, WS, confusion, SSH, IMAP, morph, QUIC
			sharedIdentity(globalClientID).prefixed("polling"), // HTTP polling
		}},
		{"registry client", perClient, []clientIdentity{
			registryIdentity("c1"),
			registryIdentity("c1").prefixed("polling"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reality := realityIdentityFor(t, srvCtx, tc.secret)
			want := allocationKey(reality, origin)
			for _, other := range tc.others {
				if got := allocationKey(other, origin); got != want {
					t.Errorf("%s keys lease %q, REALITY keys %q: one client, two addresses", other, got, want)
				}
			}

			// Against a real pool: the session that came in over another
			// transport holds the address, REALITY asks for it and gets it.
			pool, err := NewIPPool(IPPoolConfig{Network: "10.8.1.0/24", ServerIP: "10.8.1.1"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			held, err := pool.Allocate(allocationKey(tc.others[0], origin), net.ParseIP("10.8.1.4"), "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := pool.Allocate(want, held, "")
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(held) {
				t.Fatalf("REALITY got %s while the same client holds %s over another transport", got, held)
			}
		})
	}
}

// TestGlobalSecretStillSeparatesOrigins: the cross-transport lease must not
// undo the global-secret collision fix. Two boxes on the global secret at two
// origins keep two leases, on any mix of transports.
func TestGlobalSecretStillSeparatesOrigins(t *testing.T) {
	global := []byte("the-global-secret-of-this-exit-32")
	srvCtx := &serverContext{cfg: &Config{Secret: global}}
	reality := realityIdentityFor(t, srvCtx, global)

	if allocationKey(reality, "192.0.2.161") == allocationKey(sharedIdentity(globalClientID), "198.51.100.152") {
		t.Fatal("two boxes on the global secret at two origins share a lease")
	}
	if allocationKey(reality, "192.0.2.161") == allocationKey(reality, "198.51.100.152") {
		t.Fatal("two REALITY boxes on the global secret at two origins share a lease")
	}
}
