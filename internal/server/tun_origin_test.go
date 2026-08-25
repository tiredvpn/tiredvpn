package server

import (
	"net"
	"strings"
	"testing"
)

func TestAppendSplitTUNOriginRoundTrip(t *testing.T) {
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03} // [mode][ip:4][mtu:2][ver:1]

	cases := []string{"79.139.165.170", "2001:db8::1", "185.22.60.152"}
	for _, origin := range cases {
		t.Run(origin, func(t *testing.T) {
			got, gotOrigin := splitTUNOrigin(appendTUNOrigin(handshake, origin))
			if gotOrigin != origin {
				t.Errorf("origin = %q, want %q", gotOrigin, origin)
			}
			if string(got) != string(handshake) {
				t.Errorf("handshake = %x, want %x", got, handshake)
			}
		})
	}
}

func TestSplitTUNOriginWithoutExtension(t *testing.T) {
	// A payload from a client (or an older relay) has no trailer and must come
	// back byte-identical, otherwise the handshake parse shifts.
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03}
	got, origin := splitTUNOrigin(handshake)
	if origin != "" {
		t.Errorf("origin = %q, want empty", origin)
	}
	if string(got) != string(handshake) {
		t.Errorf("handshake = %x, want %x", got, handshake)
	}
}

func TestSplitTUNOriginIgnoresStrayMagic(t *testing.T) {
	// The magic can occur inside packet-ish payload bytes; without a well-formed
	// length trailer it must not be treated as an origin.
	payload := append([]byte{0x02, 10, 8, 0, 2}, tunOriginMagic...)
	payload = append(payload, 0xff, 0xff) // length claims 255 bytes, only 2 present
	got, origin := splitTUNOrigin(payload)
	if origin != "" {
		t.Errorf("origin = %q, want empty", origin)
	}
	if string(got) != string(payload) {
		t.Errorf("payload was modified: %x", got)
	}
}

func TestAppendTUNOriginEmpty(t *testing.T) {
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03}
	if got := appendTUNOrigin(handshake, ""); string(got) != string(handshake) {
		t.Errorf("empty origin changed the payload: %x", got)
	}
}

func TestAllocationKey(t *testing.T) {
	cases := []struct {
		name   string
		id     clientIdentity
		origin string
		want   string
	}{
		// Two boxes on the global secret must not share a lease - this is the
		// flap that had usa2 handing 10.8.5.2 to both the laptop and the RU hop.
		{"global gets qualified", sharedIdentity("global"), "79.139.165.170", "global@79.139.165.170"},
		{"global other origin", sharedIdentity("global"), "185.22.60.152", "global@185.22.60.152"},

		// This case is why the first fix did not work. It used to be written
		// as a "named client" that must keep its identity, and it passed under
		// the old rule for exactly the wrong reason: reality:<hex> is an HMAC
		// of the shared secret, so it is the same string for everyone holding
		// that secret. Dubai ran three different addresses under
		// reality:d3d70b6371709943 and they evicted each other every thirty
		// seconds while this test was green.
		{"reality id off a shared secret is not per-client",
			sharedIdentity("reality:4d5e13abbf0e8fd3"), "79.139.165.170", "reality:4d5e13abbf0e8fd3@79.139.165.170"},
		{"polling id off a shared secret is not per-client",
			sharedIdentity("polling:global"), "185.22.60.152", "polling:global@185.22.60.152"},

		// A registry client is unique by construction, so its lease must NOT be
		// qualified: that is what keeps its IP across a change of address.
		{"registry client untouched", registryIdentity("c1"), "79.139.165.170", "c1"},
		{"registry client keeps id on a new address", registryIdentity("c1"), "1.2.3.4", "c1"},

		{"shared without origin", sharedIdentity("global"), "", "global"},
		{"empty client", clientIdentity{}, "1.2.3.4", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allocationKey(c.id, c.origin); got != c.want {
				t.Errorf("allocationKey(%+v, %q) = %q, want %q", c.id, c.origin, got, c.want)
			}
		})
	}
}

// TestUnclassifiedIdentityIsTreatedAsShared pins the default. Whoever adds the
// next transport gets a zero clientIdentity if they forget to say where the id
// came from, and the cost of that mistake has to be a spare lease rather than
// two clients on one tunnel IP.
func TestUnclassifiedIdentityIsTreatedAsShared(t *testing.T) {
	var forgotten clientIdentity
	forgotten.id = "newtransport:whatever"

	if got := allocationKey(forgotten, "79.139.165.170"); got != "newtransport:whatever@79.139.165.170" {
		t.Errorf("an unclassified identity was not qualified: %q", got)
	}
}

// TestPrefixedKeepsProvenance covers the relabelling the polling path does. The
// prefix says which transport carried the identity; it cannot turn a secret
// every client shares into one that identifies a client.
func TestPrefixedKeepsProvenance(t *testing.T) {
	if got := sharedIdentity("global").prefixed("polling"); got.id != "polling:global" || got.perClient {
		t.Errorf("shared identity became %+v, want polling:global still shared", got)
	}
	if got := registryIdentity("c1").prefixed("polling"); got.id != "polling:c1" || !got.perClient {
		t.Errorf("registry identity became %+v, want polling:c1 still per-client", got)
	}
	if got := (clientIdentity{}).prefixed("polling"); got.id != "" {
		t.Errorf("an empty identity gained an id: %+v", got)
	}
}

func TestOriginOf(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "79.139.165.170:2064")
	if err != nil {
		t.Fatal(err)
	}
	if got := originOf(addr); got != "79.139.165.170" {
		t.Errorf("originOf = %q, want the host without the port", got)
	}
	if got := originOf(nil); got != "" {
		t.Errorf("originOf(nil) = %q, want empty", got)
	}
}

// TestSharedSecretClientsGetDistinctIPs is the Dubai case against a real pool.
// Three addresses authenticated with one global secret and got one
// reality:<hmac>, so all three asked for 10.8.2.4 and the pool handed it to all
// three: each new session evicted the live one, the evicted client reconnected
// within its keepalive window and evicted the next, and the exit logged
// "replacing LIVE connection ... last_seen=0s ago" every thirty seconds.
func TestSharedSecretClientsGetDistinctIPs(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.2.0/24", ServerIP: "10.8.2.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// One identity, because one secret. Three different clients.
	id := sharedIdentity("reality:d3d70b6371709943")
	addrs := []string{"79.139.161.161", "176.112.205.147", "185.22.60.152"}

	seen := make(map[string]string, len(addrs))
	for _, addr := range addrs {
		got, err := pool.Allocate(allocationKey(id, addr), net.ParseIP("10.8.2.4"), "")
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if other, clash := seen[got.String()]; clash {
			t.Fatalf("%s and %s both got %s under one shared identity", other, addr, got)
		}
		seen[got.String()] = addr
	}

	// Sticky per client: the same box reconnecting keeps its address, which is
	// what stops the eviction loop rather than merely spreading it out.
	first := allocationKey(id, addrs[0])
	again, err := pool.Allocate(first, net.ParseIP("10.8.2.99"), "")
	if err != nil {
		t.Fatal(err)
	}
	if seen[again.String()] != addrs[0] {
		t.Errorf("reconnect from %s got %s, which belongs to %q", addrs[0], again, seen[again.String()])
	}
}

// TestRegistryClientKeepsOneLeaseAcrossAddresses is the control for the case
// above: qualifying everything would be a trivially "safe" fix that quietly
// breaks the clients that already work, by giving a named client a fresh IP
// every time its address changes.
func TestRegistryClientKeepsOneLeaseAcrossAddresses(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.2.0/24", ServerIP: "10.8.2.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	named := registryIdentity("c1")
	home, err := pool.Allocate(allocationKey(named, "79.139.165.170"), net.ParseIP("10.8.2.7"), "")
	if err != nil {
		t.Fatal(err)
	}
	roaming, err := pool.Allocate(allocationKey(named, "185.22.60.152"), net.ParseIP("10.8.2.7"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !home.Equal(roaming) {
		t.Errorf("named client moved address and got %s instead of keeping %s", roaming, home)
	}
}

func TestGlobalClientsGetDistinctIPs(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.5.0/24", ServerIP: "10.8.5.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	laptop := allocationKey(sharedIdentity(globalClientID), "79.139.165.170")
	ruhop := allocationKey(sharedIdentity(globalClientID), "185.22.60.152")

	first, err := pool.Allocate(laptop, net.ParseIP("10.8.5.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Allocate(ruhop, net.ParseIP("10.8.5.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Equal(second) {
		t.Fatalf("both global clients got %s; they must not share a tunnel IP", first)
	}

	// Same client reconnecting keeps its address (sticky lease).
	again, err := pool.Allocate(laptop, net.ParseIP("10.8.5.9"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(first) {
		t.Errorf("reconnect got %s, want the sticky %s", again, first)
	}
}

// TestRealityIdentityIsShared covers the classification at the point it is made
// rather than at the point it is used. allocationKey can only be as right as
// what it is handed, and the reason Dubai flapped was not the rule - it was
// that reality:<hmac> arrived claiming to identify somebody.
func TestRealityIdentityIsShared(t *testing.T) {
	secret := []byte("a-shared-secret-for-everyone-32b")

	id := realityClientIdentity(secret)
	if id.perClient {
		t.Fatal("an identity derived from a secret alone cannot be per-client: every holder of that secret produces it")
	}
	if !strings.HasPrefix(id.id, "reality:") {
		t.Errorf("id = %q, want the reality: prefix", id.id)
	}

	// Two different clients, one secret: the identity is the same string, which
	// is exactly why it must not key a lease on its own.
	if other := realityClientIdentity(secret); other.id != id.id {
		t.Fatalf("the same secret gave two identities, %q and %q", id.id, other.id)
	}
	if allocationKey(id, "79.139.161.161") == allocationKey(id, "185.22.60.152") {
		t.Error("two addresses on one secret produced one lease key")
	}

	// A different secret is a different user and keeps its own identity.
	if diff := realityClientIdentity([]byte("a-different-secret-also-32-bytes")); diff.id == id.id {
		t.Error("two different secrets collapsed to one identity")
	}
}
