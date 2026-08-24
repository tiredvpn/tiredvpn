package server

import (
	"errors"
	"net"
	"sync"
	"time"
)

//go:generate go run donorprofiles_gen.go

// Per-donor ChangeCipherSpec tolerance.
//
// A prober can tell our front from the site it claims to be by sending runs of
// ChangeCipherSpec records and watching when the connection dies. In TLS 1.3
// those records mean nothing at all - they exist so middleboxes see something
// familiar - so a server's tolerance for them is pure implementation
// behaviour, and it differs between sites. crypto/tls tolerates a fixed 16
// (maxUselessRecords in common.go), which matches nobody in particular.
//
// The measurements found two different mechanisms, which is why this is not
// simply a counter:
//
//   - count: the donor dies after a fixed number of records regardless of
//     pacing. yandex.ru and ya.ru cut at 33, vk.com and the card issuers at 34.
//   - timeout: the donor has no count limit at all and cuts on elapsed
//     handshake time instead, around 9.5 seconds. sberbank.ru, gosuslugi.ru and
//     vtb.ru behave this way - at 40ms pacing they accept 240 records and at
//     10ms they accept 400 without reaching a limit.
//   - none: no limit of either kind. Both githubusercontent hosts took 1200
//     records over 48 seconds in silence.
//
// Against a timeout donor any finite count is wrong: a patient prober sending
// one record per second sees us cut at N while the real site holds until its
// deadline. That is why the mechanism travels with the number.
//
// Why this filters rather than only counts. crypto/tls has its own limit of 16
// consecutive useless records, below every count donor we measured (33 to 36),
// so left alone it fires first and we cut earlier than the site we claim to be.
// The guard therefore swallows ChangeCipherSpec records beyond the first
// instead of passing them up: TLS 1.3 ignores them anyway (RFC 8446 D.4), and
// crypto/tls never counts what it never sees. The first one is passed through
// untouched, because in TLS 1.2 it is a real handshake message and dropping it
// would break those profiles.
//
// Measured on a local reproduction rather than reasoned about: our own front
// answers a flood by failing the handshake at record 17 and then handing the
// socket to the fake website, which keeps it open. That is why the probe
// recorded us as having no limit at all - it was measuring its own ability to
// keep writing, not our tolerance.

type ccsMechanism uint8

const (
	// ccsUnmeasured means the donor is in the pool but has no measurement, so
	// the default applies. Kept distinct from count so the guard tests can name
	// which donors are running on a guess.
	ccsUnmeasured ccsMechanism = iota
	ccsCount
	ccsTimeout
	// ccsNone is a donor with no limit of either kind: raw.githubusercontent.com
	// and objects.githubusercontent.com accepted 1200 records over 48 seconds
	// without a word. Under those names we do not cut either.
	ccsNone
)

// ccsPolicy is one donor's tolerance.
type ccsPolicy struct {
	Mechanism ccsMechanism
	Limit     int
	Timeout   time.Duration
}

// donorProfile is everything measured about one donor that we have to
// reproduce. One table rather than one per property: two independent lookups
// keyed on the same name drift apart, and a donor we imitate in one respect but
// not another is worse than one we do not imitate at all.
type donorProfile struct {
	CCS         ccsPolicy
	KeyExchange keyExchange
}

// keyExchange is which group a donor negotiates.
//
// Reproducing a measured difference is not the same thing as inventing one. We
// do not answer post-quantum to our own names and classic to donor names - that
// split exists nowhere in nature and would let anyone enumerate our domains by
// probing. We answer the way the site we are claiming to be answers, which is
// the same rule the ChangeCipherSpec limit follows.
type keyExchange uint8

const (
	kxClassic keyExchange = iota
	kxHybrid
)

// defaultCCSPolicy applies to a donor with no measurement.
//
// 33, the floor of the count-based cluster among the TLS 1.3 donors: yandex.ru
// and ya.ru cut there, vk.com and the card issuers one higher. Sitting at the
// floor means we are never more tolerant than a measured donor of that kind,
// while never being the odd one out that dies first.
//
// mail.ru's measured 2 is deliberately not the default even though it is the
// strictest number in the table. It is a TLS 1.2 donor, where ChangeCipherSpec
// is a real protocol message rather than compatibility padding, so its
// tolerance says nothing about how a TLS 1.3 server behaves. Taking it as the
// default would make us cut an order of magnitude earlier than every modern
// donor in the pool, which is a signal of its own rather than caution.
var defaultCCSPolicy = ccsPolicy{Mechanism: ccsCount, Limit: 33}

// ccsPolicyFor returns the tolerance to imitate for a given SNI.
func ccsPolicyFor(sni string) ccsPolicy {
	p, ok := donorProfiles[sni]
	if !ok || p.CCS.Mechanism == ccsUnmeasured {
		return defaultCCSPolicy
	}
	return p.CCS
}

// keyExchangeFor returns the group to negotiate under a given SNI.
//
// Classic is the default and covers eleven of the thirteen donors. The two
// exceptions - raw.githubusercontent.com and objects.githubusercontent.com -
// really do negotiate ML-KEM, and answering them with classic would put us at
// odds with the donor we claim to be on roughly fifteen percent of connections,
// which is enough to check on the first packet.
//
// Dropping those two from the pool instead is not an option worth taking: both
// are in the developer category, which is the primary cover category because
// TSPU does not check those domains' addresses against the server's, and the
// category holds four names. Removing two collapses a user's rotation to
// alternating between a pair of domains.
func keyExchangeFor(sni string) keyExchange {
	if p, ok := donorProfiles[sni]; ok {
		return p.KeyExchange
	}
	return kxClassic
}

// errCCSFlood is returned once a connection has spent its tolerance. It never
// reaches the peer: the connection is closed without an alert, which is what
// the donors do.
var errCCSFlood = errors.New("reality: changecipherspec tolerance exhausted")

// ccsGuard counts plaintext ChangeCipherSpec records on the read path and
// closes the connection once the donor being imitated would have closed it.
//
// It wraps the connection below crypto/tls rather than configuring it, because
// the tolerance there is a package constant with no way in from outside, and
// forking the standard library for one integer is not a trade worth making.
//
// Counting stops when the handshake finishes. After that everything is
// ApplicationData, a 0x14 in the ciphertext means nothing, and a check on the
// hot path would cost throughput for no benefit.
type ccsGuard struct {
	net.Conn

	mu      sync.Mutex
	policy  ccsPolicy
	count   int
	done    bool // handshake finished; stop filtering
	tripped bool
	timer   *time.Timer

	// Record framing state, carried across reads because a peer chooses how the
	// stream is chopped up.
	hdr      []byte // partial record header, held back until the type is known
	bodyLeft int    // bytes of the current record body still to come
	dropBody bool   // the current record is being swallowed

	scratch []byte // read buffer
	pending []byte // filtered bytes not yet handed to the caller
}

// newCCSGuard wraps conn with the tolerance of the donor named by sni.
func newCCSGuard(conn net.Conn, sni string) *ccsGuard {
	g := &ccsGuard{Conn: conn, policy: ccsPolicyFor(sni), scratch: make([]byte, 4096)}
	if g.policy.Mechanism == ccsTimeout && g.policy.Timeout > 0 {
		// A timeout donor does not count records; it gives the handshake a
		// budget of wall-clock time. Arm it now, at the first byte, and stop it
		// when the handshake completes.
		g.timer = time.AfterFunc(g.policy.Timeout, g.trip)
	}
	return g
}

// handshakeDone stops the guard. Call it once tls.Handshake returns, whatever
// the outcome. After this the connection is pure ApplicationData, where a 0x14
// is a byte of ciphertext and filtering it would corrupt the stream.
func (g *ccsGuard) handshakeDone() {
	g.mu.Lock()
	g.done = true
	timer := g.timer
	g.timer = nil
	held := g.hdr
	g.hdr = nil
	// Anything still held back as a partial header belongs to the caller now.
	if len(held) > 0 {
		g.pending = append(g.pending, held...)
	}
	g.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
}

// trip closes the connection the way a donor does: no alert, no reply, just
// gone.
func (g *ccsGuard) trip() {
	g.mu.Lock()
	if g.done || g.tripped {
		g.mu.Unlock()
		return
	}
	g.tripped = true
	g.mu.Unlock()

	_ = g.Close()
}

func (g *ccsGuard) Read(b []byte) (int, error) {
	for {
		g.mu.Lock()
		if g.tripped {
			g.mu.Unlock()
			return 0, errCCSFlood
		}
		if n := g.drainLocked(b); n > 0 {
			g.mu.Unlock()
			return n, nil
		}
		done := g.done
		g.mu.Unlock()

		// Past the handshake there is nothing to filter, so read straight
		// through and keep the hot path free of this.
		if done {
			return g.Conn.Read(b)
		}

		n, err := g.Conn.Read(g.scratch)
		if n > 0 {
			g.mu.Lock()
			flood := g.filterLocked(g.scratch[:n])
			out := g.drainLocked(b)
			g.mu.Unlock()

			if flood {
				g.trip()
				return 0, errCCSFlood
			}
			if out > 0 {
				return out, nil
			}
			// Everything read was swallowed. Returning 0 with a nil error is
			// not allowed to mean anything, so go round again.
			if err == nil {
				continue
			}
		}
		if err != nil {
			return 0, err
		}
	}
}

// drainLocked moves buffered filtered bytes into b.
func (g *ccsGuard) drainLocked(b []byte) int {
	if len(g.pending) == 0 {
		return 0
	}
	n := copy(b, g.pending)
	g.pending = g.pending[n:]
	if len(g.pending) == 0 {
		g.pending = nil
	}
	return n
}

// filterLocked walks records in a freshly read chunk, appending everything the
// caller should see to pending and swallowing surplus ChangeCipherSpec records.
// It reports whether the donor's tolerance has been spent.
//
// Header bytes are held back rather than passed through, because a record's
// type is not known until all five are in hand and a header already delivered
// cannot be taken back.
func (g *ccsGuard) filterLocked(chunk []byte) bool {
	const recordHeaderLen = 5

	for len(chunk) > 0 {
		if g.bodyLeft > 0 {
			take := min(g.bodyLeft, len(chunk))
			if !g.dropBody {
				g.pending = append(g.pending, chunk[:take]...)
			}
			g.bodyLeft -= take
			chunk = chunk[take:]
			continue
		}

		need := recordHeaderLen - len(g.hdr)
		if len(chunk) < need {
			g.hdr = append(g.hdr, chunk...)
			return false
		}
		g.hdr = append(g.hdr, chunk[:need]...)
		chunk = chunk[need:]

		g.bodyLeft = int(g.hdr[3])<<8 | int(g.hdr[4])
		g.dropBody = false

		if g.hdr[0] == 0x14 {
			g.count++
			// The first one is a real message under TLS 1.2 and harmless under
			// TLS 1.3, so it goes through. Every one after it is padding.
			if g.count > 1 {
				g.dropBody = true
			}
			if g.overBudgetLocked() {
				g.hdr = g.hdr[:0]
				return true
			}
		}

		if !g.dropBody {
			g.pending = append(g.pending, g.hdr...)
		}
		g.hdr = g.hdr[:0]
	}
	return false
}

// overBudgetLocked reports whether the count has passed what this donor allows.
func (g *ccsGuard) overBudgetLocked() bool {
	return g.policy.Mechanism == ccsCount && g.count > g.policy.Limit
}

var _ net.Conn = (*ccsGuard)(nil)
