package server

import (
	"bytes"
	"net"
)

// globalClientID is the client identity every caller authenticated with the
// server's global secret ends up with: the shared secret carries no per-client
// information, so the server cannot tell two such clients apart by identity.
const globalClientID = "global"

// tunOriginMagic marks the optional origin extension a relay appends to the TUN
// setup payload it forwards upstream. It is deliberately placed AFTER the fixed
// [localIP:4][mtu:2][version:1] handshake: every existing exit parses those
// seven bytes and ignores the rest of the stego payload, so an older upstream
// silently drops the extension instead of choking on it.
var tunOriginMagic = []byte("TRO1")

// appendTUNOrigin returns handshake with the downstream client's origin appended
// as [magic:4][len:1][origin:N]. An empty origin returns the handshake unchanged.
func appendTUNOrigin(handshake []byte, origin string) []byte {
	if origin == "" || len(origin) > 255 {
		return handshake
	}
	out := make([]byte, 0, len(handshake)+len(tunOriginMagic)+1+len(origin))
	out = append(out, handshake...)
	out = append(out, tunOriginMagic...)
	out = append(out, byte(len(origin)))
	out = append(out, origin...)
	return out
}

// splitTUNOrigin splits a TUN setup payload into the handshake proper and the
// origin a relay attached to it. Payloads without the extension come back
// unchanged with an empty origin, so callers can treat both the same.
func splitTUNOrigin(data []byte) ([]byte, string) {
	idx := bytes.LastIndex(data, tunOriginMagic)
	if idx < 0 {
		return data, ""
	}
	rest := data[idx+len(tunOriginMagic):]
	if len(rest) < 1 {
		return data, ""
	}
	n := int(rest[0])
	if n == 0 || len(rest) != 1+n {
		// Not our trailer (a stray magic sequence inside the payload).
		return data, ""
	}
	return data[:idx], string(rest[1 : 1+n])
}

// originOf reduces a remote address to the host part, dropping the ephemeral
// port so a client keeps the same identity across reconnects.
func originOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// clientIdentity is a client's identity together with where it came from.
//
// The origin of an identity, not its spelling, decides whether it can key a
// lease. The first version of this asked whether the string equalled "global",
// which covered exactly one of the several identities the server derives from
// the shared secret: REALITY builds "reality:<hmac-of-secret>", HTTP polling
// builds "polling:global". Those are the same value for every client that
// presents that secret, so they collided exactly the way "global" did - the
// fix looked complete for six weeks while Dubai flapped every thirty seconds
// under one reality:<hmac> shared by three different addresses.
//
// A list of known prefixes would have gone stale with the next transport. The
// answer is to record what the identity was derived from where it is derived,
// which is the only place that knows.
type clientIdentity struct {
	// id is the identity as it appears in logs, metrics and the TUN registry.
	id string

	// perClient is true when id distinguishes this client from every other
	// one - it came from the client registry, where each client has its own
	// secret and its own name.
	//
	// The zero value is the safe one on purpose. An identity nobody classified
	// is treated as shared and gets qualified, which at worst costs a client a
	// second lease after it changes address; the opposite default hands two
	// clients one tunnel IP and they evict each other until one gives up.
	perClient bool
}

// sharedIdentity marks an identity derived from a credential every client
// presents - the server's global secret. Two different clients can carry the
// same value, so it cannot key a lease by itself.
func sharedIdentity(id string) clientIdentity {
	return clientIdentity{id: id}
}

// registryIdentity marks an identity that came from the client registry. It is
// unique to one client, so it keys a lease on its own and that client keeps its
// address across a change of network.
func registryIdentity(id string) clientIdentity {
	return clientIdentity{id: id, perClient: true}
}

// String lets an identity be logged where the bare id used to be.
func (c clientIdentity) String() string { return c.id }

// prefixed labels an identity with the transport that carried it, keeping where
// the identity came from. Prefixing is relabelling, not re-deriving: putting
// "polling:" in front of a shared id leaves it just as shared.
func (c clientIdentity) prefixed(transport string) clientIdentity {
	if c.id == "" {
		return c
	}
	return clientIdentity{id: transport + ":" + c.id, perClient: c.perClient}
}

// allocationKey qualifies the IP-pool lease key with the client's origin when
// the identity cannot tell two clients apart.
//
// IPPool leases are sticky per key, so keying on a shared identity hands the
// SAME tunnel IP to every client carrying it: the second one to connect takes
// over the first one's address, the first reconnects and takes it back, and
// the two flap against each other indefinitely, once per keepalive interval.
// Adding the origin gives two boxes on one secret two different leases.
//
// The origin is the downstream client's address, which on a relay arrives in
// the TRO1 trailer rather than from the socket - qualifying at the point of
// authentication instead would collapse every client behind one relay back
// into a single lease.
func allocationKey(id clientIdentity, origin string) string {
	// An empty identity keys nothing, and "@1.2.3.4" would be a key rather than
	// the absence of one. Callers that have no identity resolve one of their own
	// before they get here; this keeps the function honest for the ones that do
	// not, which is what it did before it learned about provenance.
	if id.id == "" || id.perClient || origin == "" {
		return id.id
	}
	return id.id + "@" + origin
}
