package server

import (
	"encoding/binary"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// tunClientVersionDualStack is the handshake version byte by which a client
// advertises IPv6 dual-stack support inside the tunnel. The request layout is
// unchanged at v0x04; the version byte itself is the signal.
const tunClientVersionDualStack = 0x04

// dualStackAddrs carries the IPv6 tunnel addresses appended to a v0x04
// handshake response as a trailing 32-byte block [serverIP6:16][clientIP6:16].
type dualStackAddrs struct {
	ServerIP6 net.IP
	ClientIP6 net.IP
}

// deriveDualStackAddrs builds the IPv6 tunnel addresses from the configured
// -ip-pool-v6 prefix using the pool's authoritative derivation rule (see
// deriveServerIP6/deriveClientIP6 in ippool.go): the server takes prefix::1
// and the client takes the prefix with its assigned IPv4 address in the low
// 32 bits. Returns nil when no (valid) IPv6 pool is configured, which keeps
// the response byte-identical to a non-dual-stack server.
//
// A lease with no usable v6 derivation (reserved address, non-IPv4 lease)
// also yields nil — the session degrades to IPv4-only — but is logged, since
// it means the v4 pool bounds overlap the reserved space.
func deriveDualStackAddrs(poolV6 string, clientIP net.IP) *dualStackAddrs {
	prefix, err := parsePoolV6(poolV6)
	if err != nil || prefix == nil {
		return nil
	}
	clientIP6, err := deriveClientIP6(prefix, clientIP)
	if err != nil {
		log.Warn("Dual-stack: no tunnel IPv6 for lease %s: %v; session stays IPv4-only", clientIP, err)
		return nil
	}
	return &dualStackAddrs{
		ServerIP6: deriveServerIP6(prefix),
		ClientIP6: clientIP6,
	}
}

// tunHandshakeCaps describes the optional capabilities an exit advertises in
// the handshake response flags byte and extended layouts.
type tunHandshakeCaps struct {
	portHopping bool
	portStart   int
	portEnd     int
	hopInterval int    // seconds (<=0 defaults to 60)
	hopStrategy byte   // 0=random, 1=sequential, 2=fibonacci
	hopSeed     []byte // truncated to 32 bytes
	mtuProbe    bool   // exit echoes auto-MTU probe frames (advertised to v3+)
}

// buildTUNHandshakeResponse builds the TUN-mode handshake response payload
// (without any transport framing) for a client of the given handshake
// version:
//
//	legacy (9 bytes): [status:1][serverIP:4][clientIP:4]
//	v1 (14 bytes):    + [flags:1][portStart:2][portEnd:2]
//	v2 (20+ bytes):   + [hopInterval:4][strategy:1][seedLen:1][seed:0-32]
//	flags-only (10B): [status:1][serverIP:4][clientIP:4][flags:1]
//	dual-stack:       version-dependent layout + [serverIP6:16][clientIP6:16]
//
// The dual-stack flag and block are emitted only for clients at version >=
// 0x04 with dual non-nil; every other combination produces byte-identical
// output to the pre-dual-stack code. Callers wrap the payload in their
// transport's own framing (morph/confusion/h2/polling).
func buildTUNHandshakeResponse(clientVersion byte, serverIP, clientIP net.IP, caps tunHandshakeCaps, dual *dualStackAddrs) []byte {
	var flags byte
	if caps.portHopping && clientVersion >= 0x01 {
		flags |= 0x01
	}
	if caps.mtuProbe && clientVersion >= 0x03 {
		flags |= tun.ProbeCapFlag
	}
	wantDual := dual != nil && clientVersion >= tunClientVersionDualStack
	if wantDual {
		flags |= tun.DualStackCapFlag
	}

	var resp []byte
	switch {
	case flags&0x01 != 0 && clientVersion >= 0x02:
		// Extended v2: full port-hop config.
		seed := caps.hopSeed
		if len(seed) > 32 {
			seed = seed[:32]
		}
		resp = make([]byte, 20+len(seed))
		binary.BigEndian.PutUint16(resp[10:12], uint16(caps.portStart))
		binary.BigEndian.PutUint16(resp[12:14], uint16(caps.portEnd))
		hopInterval := caps.hopInterval
		if hopInterval <= 0 {
			hopInterval = 60
		}
		binary.BigEndian.PutUint32(resp[14:18], uint32(hopInterval))
		resp[18] = caps.hopStrategy
		resp[19] = byte(len(seed))
		copy(resp[20:], seed)
	case flags&0x01 != 0:
		// Extended v1: port range only.
		resp = make([]byte, 14)
		binary.BigEndian.PutUint16(resp[10:12], uint16(caps.portStart))
		binary.BigEndian.PutUint16(resp[12:14], uint16(caps.portEnd))
	case flags != 0 || clientVersion >= tunClientVersionDualStack:
		// Flags-only form: carries the auto-MTU probe (v3) and/or dual-stack
		// (v4) bits when no port-hop range is advertised.
		//
		// A v0x04 client always gets this form even when every flag is clear,
		// so the flags byte is unconditionally present on the wire for it. That
		// lets the client read a fixed 10-byte prefix instead of stopping at 9
		// and waiting to see whether a tenth byte shows up: that wait would add
		// an observable pause to every connect and, worse, could consume the
		// first byte of downstream tunnel traffic and desync the packet loop.
		// Versions below 0x04 are unaffected — their bytes are unchanged.
		resp = make([]byte, 10)
	default:
		resp = make([]byte, 9)
	}
	resp[0] = 0x00 // Success
	copy(resp[1:5], serverIP.To4())
	copy(resp[5:9], clientIP.To4())
	if len(resp) >= 10 {
		resp[9] = flags
	}

	if wantDual {
		block := make([]byte, 32)
		copy(block[0:16], dual.ServerIP6.To16())
		copy(block[16:32], dual.ClientIP6.To16())
		resp = append(resp, block...)
	}
	return resp
}

// portHopStrategyByte maps the configured hop strategy name to its wire byte.
func portHopStrategyByte(strategy string) byte {
	switch strategy {
	case "sequential":
		return 0x01
	case "fibonacci":
		return 0x02
	default:
		return 0x00 // random
	}
}

// downstreamDualStackAddrs picks the IPv6 tunnel addresses for the handshake
// response a transport sends to its client: on a relay they come from the
// upstream exit (carried on the relay sink, nil when the exit did not
// negotiate dual-stack, which degrades the downstream client to v4-only);
// on a terminating exit they are derived from the local -ip-pool-v6 prefix.
func downstreamDualStackAddrs(sink tunPacketSink, poolV6 string, clientIP net.IP) *dualStackAddrs {
	if rs, ok := sink.(*relayTUNSink); ok {
		return rs.dualAddrs()
	}
	return deriveDualStackAddrs(poolV6, clientIP)
}

// recordDualStackSession counts one dual-stack negotiation: the response being
// built carries v6 addresses for a dual-capable (v0x04+) client. Called by
// every TUN transport at the point it answers a client, both on the
// terminating exit (pool-derived addrs) and on a relay (exit-assigned addrs
// forwarded downstream), so one session setup counts exactly once and a
// reconnect — which is a new session — counts again.
func recordDualStackSession(srvCtx *serverContext, clientVersion uint8, dual *dualStackAddrs) {
	if dual == nil || clientVersion < tunClientVersionDualStack || srvCtx == nil || srvCtx.metrics == nil {
		return
	}
	srvCtx.metrics.ipv6Metrics.RecordTunnelDualStackSession()
}

// recordRelayedDualStackSession counts a dual-stack negotiation on the plain
// relay path, which forwards the exit's handshake response to the downstream
// client verbatim instead of building one of its own. The exit's response is
// the only authority there, so the addresses are read back out of it; a
// response without the dual-stack flag counts nothing, exactly as a nil
// dualStackAddrs would.
func recordRelayedDualStackSession(srvCtx *serverContext, clientVersion uint8, resp []byte) {
	caps, ok := tun.ParseTUNHandshakeCapabilities(resp)
	if !ok || !caps.DualStackEnabled {
		return
	}
	recordDualStackSession(srvCtx, clientVersion, &dualStackAddrs{
		ServerIP6: caps.ServerIP6,
		ClientIP6: caps.ClientIP6,
	})
}

// frameConfusionTUNResponse wraps a handshake response payload in the
// confusion transport's length-prefixed frame: [len:4][payload]. On the wire
// the payload offsets shift by 4 (status@4, serverIP@5:9, clientIP@9:13) —
// the historical 13-byte frame for the legacy 9-byte payload.
func frameConfusionTUNResponse(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}
