package strategy

import (
	"encoding/binary"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// meekStreamTracker tells the keepalive feeder where it may splice a synthetic
// keepalive frame into the downlink byte stream without corrupting it.
//
// A polling session carries one of two streams, chosen by the first uplink
// byte exactly as the server chooses (runPollingSessionRelay):
//
//   - 0x02: TUN mode. The downlink is the TUN handshake response followed by
//     [len:4][payload] frames, and [0,0,0,0] is a keepalive frame the TUN relay
//     accepts.
//   - anything else: SOCKS mode, [addrLen:2][addr] and then a raw byte stream
//     to the proxied target. Nothing may ever be added to it - four zero bytes
//     in the middle of a proxied download are just corruption.
//
// In TUN mode an empty receive buffer does not mean the reader sits between
// frames: a poll response is cut at 16 KiB regardless of framing, so the reader
// is routinely parked inside a frame waiting for the next poll. The tracker
// follows the framing of every byte handed to the receive buffer, so "buffer
// empty and tracker at a boundary" means the reader has consumed exactly a
// whole number of frames.
//
// Anything the tracker cannot account for (a failed handshake, a layout it does
// not know, an impossible frame length) turns splicing off for the rest of the
// session. That degrades to "no synthetic keepalives", never to a corrupted
// stream.
type meekStreamTracker struct {
	// Uplink sniff: the first bytes the client writes.
	up  [8]byte
	upN int

	state meekDownState

	// hs collects the handshake response until its length is known.
	hs     [meekHandshakeMax]byte
	hsN    int
	hsNeed int

	hdr      [4]byte
	hdrN     int
	bodyLeft int
}

type meekDownState uint8

const (
	meekDownUnknown   meekDownState = iota // no downlink byte seen yet
	meekDownRaw                            // SOCKS stream: never splice
	meekDownHandshake                      // inside the TUN handshake response
	meekDownFrames                         // inside the TUN frame stream
	meekDownBroken                         // lost track: never splice again
)

const (
	// meekTUNMode is the first uplink byte of a TUN-mode session, the value the
	// server dispatches on.
	meekTUNMode = 0x02

	// Handshake layout knowledge, mirrored from the server's
	// buildTUNHandshakeResponse and the client's readResponseTail (internal/tun
	// imports this package, so the constants cannot be shared).
	meekHSBase          = 9    // [status:1][serverIP:4][clientIP:4]
	meekHSVersionFlags  = 0x04 // from this client version on, the flags byte is always sent
	meekHSFlagPortHop   = 0x01 // port-hop layouts: never sent by a polling exit
	meekHSFlagDualStack = 0x04 // trailing [serverIP6:16][clientIP6:16]
	meekHandshakeMax    = meekHSBase + 1 + 32

	// meekMaxFrame is the TUN protocol frame ceiling; a longer length means the
	// tracker is misaligned.
	meekMaxFrame = 65535
)

// observeUplink records the first bytes the client writes. Only the first
// eight matter: [mode:1][localIP:4][mtu:2][version:1] for a TUN handshake.
func (t *meekStreamTracker) observeUplink(p []byte) {
	if t.upN < len(t.up) {
		t.upN += copy(t.up[t.upN:], p)
	}
}

// uplinkSettled reports that further uplink bytes cannot change what the
// tracker decides: the version byte is in, or the downlink has started (the
// stream kind and handshake version are read at the first downlink byte).
func (t *meekStreamTracker) uplinkSettled() bool {
	return t.upN == len(t.up) || t.state != meekDownUnknown
}

// pastHandshake reports that the TUN handshake response has been fully handed
// to the receive buffer.
func (t *meekStreamTracker) pastHandshake() bool {
	return t.state == meekDownFrames
}

// markBroken stops splicing for the rest of the session. It is logged because
// it silently brings back the relay's 30s idle teardown for this meek session.
func (t *meekStreamTracker) markBroken(reason string) {
	t.state = meekDownBroken
	log.Debug("HTTP Polling: keepalive feeder off for this session: %s", reason)
}

// observeDownlink accounts for bytes appended to the receive buffer, in order.
func (t *meekStreamTracker) observeDownlink(p []byte) {
	for len(p) > 0 {
		switch t.state {
		case meekDownUnknown:
			if t.upN == 0 || t.up[0] != meekTUNMode {
				t.state = meekDownRaw
				continue
			}
			t.state = meekDownHandshake
		case meekDownRaw, meekDownBroken:
			return
		case meekDownHandshake:
			p = t.consumeHandshake(p)
		case meekDownFrames:
			p = t.consumeFrames(p)
		}
	}
}

// consumeHandshake eats handshake response bytes and returns the rest.
func (t *meekStreamTracker) consumeHandshake(p []byte) []byte {
	for len(p) > 0 && t.state == meekDownHandshake {
		want := t.hsNeed
		if want == 0 {
			// Length not known yet: gather up to the part that decides it.
			want = meekHSBase
			if t.hsVersion() >= meekHSVersionFlags {
				want = meekHSBase + 1
			}
		}
		n := copy(t.hs[t.hsN:want], p)
		t.hsN += n
		p = p[n:]
		if t.hsN < want {
			return p
		}
		if t.hsNeed == 0 {
			var why string
			t.hsNeed, why = t.handshakeLen()
			if t.hsNeed < 0 {
				t.markBroken(why)
				return nil
			}
		}
		if t.hsN == t.hsNeed {
			t.state = meekDownFrames
		}
	}
	return p
}

// hsVersion is the handshake version the client asked for, read the way the
// server reads it: a 6-byte request (no version byte) is version 1.
func (t *meekStreamTracker) hsVersion() byte {
	if t.upN < len(t.up) {
		return 0x01
	}
	return t.up[7]
}

// handshakeLen returns the full handshake response length once its deciding
// prefix is in hs, or -1 and a reason when the session failed or the layout is
// not one a polling exit sends.
func (t *meekStreamTracker) handshakeLen() (int, string) {
	if t.hs[0] != 0x00 {
		return -1, "TUN handshake refused" // nothing framed follows
	}
	if t.hsVersion() < meekHSVersionFlags {
		// A polling exit builds its response with no advertised capabilities,
		// so a pre-v4 client gets the bare 9-byte form. (The client itself
		// resolves a possible tenth byte with a timed peek the tracker cannot
		// replicate; a server that ever sends one misaligns the tracker, which
		// the frame-length check below catches.)
		return meekHSBase, ""
	}
	flags := t.hs[meekHSBase]
	if flags&meekHSFlagPortHop != 0 {
		return -1, "handshake advertises port hopping, a layout polling exits never send"
	}
	n := meekHSBase + 1
	if flags&meekHSFlagDualStack != 0 {
		n += 32
	}
	return n, ""
}

// consumeFrames eats [len:4][payload] frames and returns nothing (it always
// consumes all of p or stops the tracker).
func (t *meekStreamTracker) consumeFrames(p []byte) []byte {
	for len(p) > 0 {
		if t.bodyLeft > 0 {
			n := min(t.bodyLeft, len(p))
			t.bodyLeft -= n
			p = p[n:]
			continue
		}
		n := copy(t.hdr[t.hdrN:], p)
		t.hdrN += n
		p = p[n:]
		if t.hdrN < len(t.hdr) {
			return nil
		}
		t.hdrN = 0
		l := binary.BigEndian.Uint32(t.hdr[:])
		if l > meekMaxFrame {
			t.markBroken("frame length over the protocol ceiling, lost framing")
			return nil
		}
		t.bodyLeft = int(l)
	}
	return nil
}

// atFrameBoundary reports whether everything handed to the receive buffer so
// far ends exactly on a TUN frame boundary, so a whole keepalive frame may be
// appended.
func (t *meekStreamTracker) atFrameBoundary() bool {
	return t.state == meekDownFrames && t.hdrN == 0 && t.bodyLeft == 0
}
