package tls

import "testing"

// Capability bits negotiate optional behaviour inside the sealed session_id,
// which is the only place that works for a staged rollout.
//
// The alternative - an option on both command lines, documented as "must match
// the client setting" - can never be switched on: a rollout always has a window
// where one side has been updated and the other has not, so the matching
// requirement is violated by construction at some point. A bit in the payload
// has no such window: the server learns what the client supports before it
// answers anything.
func TestCapabilityBitsRoundTrip(t *testing.T) {
	f := newAuthFixture(t)

	want := AuthPayload{
		Version: [3]byte{1, 4, 0},
		Flags:   AuthFlagExporterBinding | AuthFlagReshapeCapable,
		Time:    1756000000,
		ShortID: ShortIDFor([]byte("a-secret")),
	}

	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, want)
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}
	got, err := OpenSessionID(f.serverPriv.Bytes(), peerPub, f.hello, f.random, sid)
	if err != nil {
		t.Fatalf("OpenSessionID: %v", err)
	}

	if !got.HasFlag(AuthFlagExporterBinding) {
		t.Error("exporter-binding bit lost in transit")
	}
	if !got.HasFlag(AuthFlagReshapeCapable) {
		t.Error("reshape-capable bit lost in transit")
	}
	if got.Flags != want.Flags {
		t.Fatalf("flags = %#02x, want %#02x", got.Flags, want.Flags)
	}
}

// TestCapabilityBitsAreIndependent guards the thing that breaks quietly: a bit
// defined at the wrong offset would read as another capability being set.
func TestCapabilityBitsAreIndependent(t *testing.T) {
	if AuthFlagExporterBinding == AuthFlagReshapeCapable {
		t.Fatal("two capabilities share a bit")
	}
	if AuthFlagExporterBinding&AuthFlagReshapeCapable != 0 {
		t.Fatal("capability bits overlap")
	}

	only := AuthPayload{Flags: AuthFlagReshapeCapable}
	if only.HasFlag(AuthFlagExporterBinding) {
		t.Error("reshape bit reads as the exporter-binding bit")
	}
	if !only.HasFlag(AuthFlagReshapeCapable) {
		t.Error("reshape bit does not read as itself")
	}

	none := AuthPayload{}
	if none.HasFlag(AuthFlagReshapeCapable) {
		t.Error("an empty payload advertises a capability")
	}
}

// TestOldClientAdvertisesNothing is the compatibility direction that matters
// for the server: a client that predates a capability sends a zero bit, and the
// server must read that as "do not do this to them" rather than as an error.
func TestOldClientAdvertisesNothing(t *testing.T) {
	f := newAuthFixture(t)

	// An older client: exporter binding only, no reshape bit.
	old := AuthPayload{
		Version: [3]byte{1, 3, 27},
		Flags:   AuthFlagExporterBinding,
		Time:    1756000000,
		ShortID: ShortIDFor([]byte("a-secret")),
	}
	sid, err := SealSessionID(f.clientEph, f.serverPriv.PublicKey().Bytes(), f.hello, f.random, old)
	if err != nil {
		t.Fatalf("SealSessionID: %v", err)
	}
	peerPub, err := ExtractPeerX25519(f.hello)
	if err != nil {
		t.Fatalf("ExtractPeerX25519: %v", err)
	}
	got, err := OpenSessionID(f.serverPriv.Bytes(), peerPub, f.hello, f.random, sid)
	if err != nil {
		t.Fatalf("an older client's payload must still open: %v", err)
	}
	if got.HasFlag(AuthFlagReshapeCapable) {
		t.Fatal("an older client appears reshape-capable")
	}
}
