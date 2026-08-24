package server

import (
	"encoding/binary"
	"net"

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

// deriveDualStackAddrs builds placeholder IPv6 tunnel addresses from the
// configured -ip-pool-v6 prefix: the server takes prefix::1 and the client
// takes the prefix with its assigned IPv4 address in the low 32 bits. Returns
// nil when no (valid) IPv6 pool is configured, which keeps the response
// byte-identical to a non-dual-stack server. Phase 2 replaces this derivation
// with the real IPv6 address pool; only the address source changes.
func deriveDualStackAddrs(poolV6 string, clientIP net.IP) *dualStackAddrs {
	if poolV6 == "" {
		return nil
	}
	ip, network, err := net.ParseCIDR(poolV6)
	if err != nil || ip.To4() != nil {
		return nil
	}
	base := network.IP.To16()
	if base == nil {
		return nil
	}

	server6 := make(net.IP, net.IPv6len)
	copy(server6, base)
	server6[net.IPv6len-1] = 1 // prefix::1

	client6 := make(net.IP, net.IPv6len)
	copy(client6, base)
	if v4 := clientIP.To4(); v4 != nil {
		copy(client6[12:], v4) // prefix | client-v4-uint32
	} else {
		client6[net.IPv6len-1] = 2
	}

	return &dualStackAddrs{ServerIP6: server6, ClientIP6: client6}
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
	case flags != 0:
		// Flags-only form: carries the auto-MTU probe (v3) and/or dual-stack
		// (v4) bits when no port-hop range is advertised.
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
