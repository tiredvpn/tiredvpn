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
//
// Against a timeout donor any finite count is wrong: a patient prober sending
// one record per second sees us cut at N while the real site holds until its
// deadline. That is why the mechanism travels with the number.

type ccsMechanism uint8

const (
	// ccsUnmeasured means the donor is in the pool but has no measurement, so
	// the default applies. Kept distinct from count so the guard tests can name
	// which donors are running on a guess.
	ccsUnmeasured ccsMechanism = iota
	ccsCount
	ccsTimeout
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

	mu        sync.Mutex
	policy    ccsPolicy
	count     int
	remaining int    // bytes left in the record body being skipped
	carry     []byte // partial record header held across reads
	done      bool   // handshake finished; stop looking
	tripped   bool
	timer     *time.Timer
}

// newCCSGuard wraps conn with the tolerance of the donor named by sni.
func newCCSGuard(conn net.Conn, sni string) *ccsGuard {
	g := &ccsGuard{Conn: conn, policy: ccsPolicyFor(sni)}
	if g.policy.Mechanism == ccsTimeout && g.policy.Timeout > 0 {
		// A timeout donor does not count records; it gives the handshake a
		// budget of wall-clock time. Arm it now, at the first byte, and stop it
		// when the handshake completes.
		g.timer = time.AfterFunc(g.policy.Timeout, g.trip)
	}
	return g
}

// handshakeDone stops the guard. Call it once tls.Handshake returns, whatever
// the outcome.
func (g *ccsGuard) handshakeDone() {
	g.mu.Lock()
	g.done = true
	timer := g.timer
	g.timer = nil
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
	g.mu.Lock()
	if g.tripped {
		g.mu.Unlock()
		return 0, errCCSFlood
	}
	g.mu.Unlock()

	n, err := g.Conn.Read(b)
	if n > 0 && g.inspect(b[:n]) {
		g.trip()
		return 0, errCCSFlood
	}
	return n, err
}

// inspect walks record headers in a freshly read chunk and reports whether the
// budget is spent. Only headers matter, so record bodies are skipped by their
// declared length - which is also what keeps a 0x14 byte inside a record body
// from being counted as a record.
func (g *ccsGuard) inspect(chunk []byte) bool {
	const recordHeaderLen = 5

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.done || g.policy.Mechanism != ccsCount {
		return false
	}

	for len(chunk) > 0 {
		if g.remaining > 0 {
			skip := min(g.remaining, len(chunk))
			g.remaining -= skip
			chunk = chunk[skip:]
			continue
		}

		need := recordHeaderLen - len(g.carry)
		if len(chunk) < need {
			g.carry = append(g.carry, chunk...)
			return false
		}
		g.carry = append(g.carry, chunk[:need]...)
		chunk = chunk[need:]

		hdr := g.carry
		g.remaining = int(hdr[3])<<8 | int(hdr[4])
		isCCS := hdr[0] == 0x14
		g.carry = g.carry[:0]

		if isCCS {
			g.count++
			if g.count > g.policy.Limit {
				return true
			}
		}
	}
	return false
}

var _ net.Conn = (*ccsGuard)(nil)
