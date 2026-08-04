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

// allocationKey qualifies the IP-pool lease key with the client's origin when
// the client has no identity of its own.
//
// Every client on the global secret authenticates as "global", and IPPool
// leases are sticky per client key, so keying on "global" alone hands the SAME
// tunnel IP to every such client: the second one to connect takes over the
// first one's address, the first reconnects and takes it back, and the two
// flap against each other indefinitely (once per keepalive interval). Adding
// the origin gives two boxes on one secret two different leases. Named clients
// (Redis/panel identities) are already unique and keep their stable key, so
// their IP survives a change of address.
func allocationKey(clientID, origin string) string {
	if clientID != globalClientID || origin == "" {
		return clientID
	}
	return clientID + "@" + origin
}
