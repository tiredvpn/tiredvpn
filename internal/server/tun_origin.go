package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

// tunClientTagMagic marks the optional client-tag extension a relay appends
// to the TUN setup payload, before the origin trailer: [magic:4][len:1][tag:N].
// It sits before TRO1 because splitTUNOrigin requires its own trailer to be
// last. Both are after the fixed seven bytes, which is all any exit parses,
// so an exit that knows neither drops both.
//
// The origin alone was not enough: it is the downstream client's IP, and two
// clients behind one NAT share it, so they shared one lease on the exit and
// evicted each other every half minute - the field case behind the msk
// relays. The tag tells them apart (relayClientTag).
var tunClientTagMagic = []byte("TRC1")

// appendTUNClientTag returns handshake with tag appended. An empty tag
// returns it unchanged.
func appendTUNClientTag(handshake []byte, tag string) []byte {
	if tag == "" || len(tag) > 255 {
		return handshake
	}
	out := make([]byte, 0, len(handshake)+len(tunClientTagMagic)+1+len(tag))
	out = append(out, handshake...)
	out = append(out, tunClientTagMagic...)
	out = append(out, byte(len(tag)))
	out = append(out, tag...)
	return out
}

// splitTUNClientTag splits a TUN setup payload into the handshake proper and
// the client tag a relay attached. Call it after splitTUNOrigin: the origin
// trailer is the outer one. A payload without the extension comes back
// unchanged with an empty tag.
func splitTUNClientTag(data []byte) ([]byte, string) {
	idx := bytes.LastIndex(data, tunClientTagMagic)
	if idx < 0 {
		return data, ""
	}
	rest := data[idx+len(tunClientTagMagic):]
	if len(rest) < 1 {
		return data, ""
	}
	n := int(rest[0])
	if n == 0 || len(rest) != 1+n {
		return data, ""
	}
	return data[:idx], string(rest[1 : 1+n])
}

// relayClientTag is the tag a relay attaches for a downstream client whose
// identity it knows and whose address it is about to forward.
//
// A client with its own credential gets its own id: two such clients behind
// one NAT then hold two leases on the exit, and each keeps its address
// across reconnects and across a change of transport.
//
// Clients that share one credential - the server's global secret - cannot be
// told apart by anything durable they send, so there is nothing stable to
// key on and the tag is drawn per downstream session. Two boxes behind one
// NAT then hold two leases instead of fighting over one, and each keeps its
// address while it reconnects: a reconnect asks for the address it holds,
// and the exit hands the lease from the session before over to the new tag
// once no session holds it (takeOverSharedLease). A box that reconnects
// after something else took that address gets a new one, as it would after
// a lease expiry.
func relayClientTag(id clientIdentity) string {
	if id.perClient && id.leaseID() != "" {
		return "c" + id.leaseID()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return "s" + hex.EncodeToString(b[:])
}

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
// fix looked complete for six weeks while node D flapped every thirty seconds
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

	// lease is the credential behind id, without the transport's label: the
	// registry client's ID, or "global" for the shared secret. One client
	// presents one credential over every transport, so this is what keys its
	// tunnel address. Empty means id itself.
	//
	// It used to be id, and id differs by transport: REALITY says
	// "reality:<hmac-of-secret>", HTTP polling "polling:global", the rest
	// "global". A client that moved from Geneva to REALITY in the middle of a
	// session - the strategy upgrade - arrived as somebody else and was handed
	// another address, so the move could never be committed.
	lease string
}

// leaseID is the identity a lease is keyed on - see lease.
func (c clientIdentity) leaseID() string {
	if c.lease != "" {
		return c.lease
	}
	return c.id
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
	return clientIdentity{id: transport + ":" + c.id, perClient: c.perClient, lease: c.leaseID()}
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
func allocationKey(id clientIdentity, origin, clientTag string) string {
	// An empty identity keys nothing, and "@1.2.3.4" would be a key rather than
	// the absence of one. Callers that have no identity resolve one of their own
	// before they get here; this keeps the function honest for the ones that do
	// not, which is what it did before it learned about provenance.
	if id.id == "" || id.perClient {
		return id.leaseID()
	}
	key := id.leaseID()
	if origin != "" {
		key += "@" + origin
	}
	// The tag a relay attached for its downstream client, which the origin
	// cannot tell apart behind a NAT. Only a relay sends one.
	if clientTag != "" {
		key += "#" + clientTag
	}
	return key
}

// allocateTunnelIP is the one way a TUN session gets its address: the lease
// keyed by allocationKey, after folding in every lease the client still holds
// under a key an older server spelled for it (legacyAllocationKeys).
func allocateTunnelIP(srvCtx *serverContext, id clientIdentity, origin, clientTag string, requested net.IP) (net.IP, error) {
	key := allocationKey(id, origin, clientTag)
	keys, prefixes := legacyAllocationKeys(srvCtx, id, origin)
	// Bounded: the Redis search for old leases must not hold a handshake up
	// for long (adoptScanTimeout); one that runs out is retried next time.
	ctx, cancel := context.WithTimeout(context.Background(), adoptScanTimeout)
	defer cancel()
	srvCtx.ipPool.AdoptAll(ctx, keys, prefixes, key)
	takeOverSharedLease(srvCtx, id, origin, clientTag, key, requested)
	return srvCtx.ipPool.Allocate(key, requested, "")
}

// takeOverSharedLease hands a client on a shared credential behind a relay
// the address it asks for back, when the lease on it is another session tag
// of the same credential and origin and no session holds it.
//
// The relay draws such a client's tag per session (relayClientTag), so every
// reconnect came with a new lease key. The reconnect asks for the address the
// client holds, but the lease from the session before still held it -
// permanent, as requested leases are - and the client got a new address on
// every reconnect while the old leases piled up (fix14 stand, twocli shared).
// The client that asks is the one that had it, or another box on the same
// secret behind the same NAT, which could take it over anyway; a session
// that holds the address keeps it.
func takeOverSharedLease(srvCtx *serverContext, id clientIdentity, origin, clientTag, key string, requested net.IP) {
	if clientTag == "" || origin == "" || requested == nil || requested.IsUnspecified() ||
		srvCtx.sharedTUN == nil || srvCtx.sharedTUN.Serving(requested) {
		return
	}
	// Only from a drawn tag ("s", relayClientTag) of the same credential and
	// origin: a client with its own credential keys its lease by its id and
	// is never under this prefix.
	srvCtx.ipPool.TakeOver(requested, allocationKey(id, origin, "")+"#s", key)
}

// legacyAllocationKeys lists the keys a server before the credential lease
// could have spelled for this client, over any transport: the plain one,
// HTTP polling's "polling:" one, and REALITY's "reality:<hmac>@origin" (always
// origin-qualified - it used to be classified as shared even for a registry
// client). The REALITY key needs the credential's secret, looked up here.
//
// All of them, not just the incoming transport's: a client whose lease was
// taken over REALITY and who comes back over Geneva would otherwise get a new
// address and leave the REALITY lease behind. Requested leases are permanent
// in Redis, so an orphan never goes away on its own. Drop this once every exit
// has run a release with the credential lease.
//
// prefixes names keys by their start instead: a registry client's REALITY
// lease under ANY origin, "reality:<hmac>@". Its key no longer has an origin,
// so the lease it took from another network is its own, and looking only under
// the current origin left that one behind and handed out a new address. On the
// global secret the origin is what tells boxes apart, and another origin's
// REALITY lease is somebody else's: there only the current origin's key is
// listed.
func legacyAllocationKeys(srvCtx *serverContext, id clientIdentity, origin string) (keys, prefixes []string) {
	lease := id.leaseID()
	if lease == "" {
		return nil, nil
	}
	qualify := func(k string, shared bool) string {
		if !shared || origin == "" {
			return k
		}
		return k + "@" + origin
	}
	keys = []string{
		qualify(lease, !id.perClient),
		qualify("polling:"+lease, !id.perClient),
	}
	if secret := credentialSecret(srvCtx, lease, id.perClient); len(secret) > 0 {
		realityKey := realityClientIdentity(secret, clientIdentity{}).id
		if id.perClient {
			prefixes = append(prefixes, realityKey+"@")
		} else {
			keys = append(keys, qualify(realityKey, true))
		}
	}
	return keys, prefixes
}

// credentialSecret is the secret behind a lease identity: the global secret,
// or the registry client's own.
func credentialSecret(srvCtx *serverContext, lease string, perClient bool) []byte {
	if !perClient {
		if lease == globalClientID && srvCtx.cfg != nil {
			return srvCtx.cfg.Secret
		}
		return nil
	}
	if srvCtx.registry == nil {
		return nil
	}
	if c := srvCtx.registry.GetByID(lease); c != nil {
		return []byte(c.Secret)
	}
	return nil
}
