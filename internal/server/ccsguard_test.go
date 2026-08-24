package server

import (
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
)

// ccsRecord is one plaintext ChangeCipherSpec record.
var ccsRecord = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

// feedGuard writes stream into a guard through a pipe and reports how many
// bytes it managed to read before the guard, if ever, cut it off.
func feedGuard(t *testing.T, g *ccsGuard, stream []byte, chunk int) (int, error) {
	t.Helper()

	read := 0
	buf := make([]byte, chunk)
	for read < len(stream) {
		n, err := g.Read(buf)
		read += n
		if err != nil {
			return read, err
		}
		if n == 0 {
			return read, io.ErrNoProgress
		}
	}
	return read, nil
}

func TestCCSGuardCountMechanism(t *testing.T) {
	t.Parallel()

	// yandex.ru is count-based at 33, so a short burst is ordinary traffic and
	// only a flood past the limit is not. The earlier figure of 1 came from a
	// probe that wrote a handshake message with no record header, so the server
	// was reacting to garbage rather than to ClientHello.
	if p := ccsPolicyFor("yandex.ru"); p.Mechanism != ccsCount || p.Limit != 33 {
		t.Fatalf("yandex.ru policy = %+v, want count/33", p)
	}

	t.Run("a burst inside the limit passes", func(t *testing.T) {
		g := newCCSGuard(&scriptConn{data: repeat(ccsRecord, 33)}, "yandex.ru")
		if _, err := feedGuard(t, g, repeat(ccsRecord, 33), 64); err != nil {
			t.Fatalf("33 records were rejected: %v", err)
		}
	})

	t.Run("one past the limit closes", func(t *testing.T) {
		stream := repeat(ccsRecord, 40)
		g := newCCSGuard(&scriptConn{data: stream}, "yandex.ru")
		_, err := feedGuard(t, g, stream, 64)
		if !errors.Is(err, errCCSFlood) {
			t.Fatalf("err = %v, want errCCSFlood", err)
		}
	})

	t.Run("a more tolerant donor allows more", func(t *testing.T) {
		// vk.com sits at 34, so the record that kills a yandex connection is
		// still fine here. This is the whole reason the number is per donor.
		stream := repeat(ccsRecord, 34)
		g := newCCSGuard(&scriptConn{data: stream}, "vk.com")
		if _, err := feedGuard(t, g, stream, 64); err != nil {
			t.Fatalf("34 records under vk.com were rejected: %v", err)
		}
	})
}

// TestCCSGuardTimeoutMechanism covers the donors with no count limit at all.
// Against them any finite count is wrong: a patient prober sending one record
// per second would see us cut at N while the real site holds to its deadline.
func TestCCSGuardTimeoutMechanism(t *testing.T) {
	t.Parallel()

	if p := ccsPolicyFor("sberbank.ru"); p.Mechanism != ccsTimeout {
		t.Fatalf("sberbank.ru policy = %+v, want the timeout mechanism", p)
	}

	t.Run("no count limit", func(t *testing.T) {
		// Far more records than any count-based donor tolerates, and the guard
		// must not care.
		stream := repeat(ccsRecord, 400)
		g := newCCSGuard(&scriptConn{data: stream}, "sberbank.ru")
		if _, err := feedGuard(t, g, stream, 128); err != nil {
			t.Fatalf("a timeout donor cut on count: %v", err)
		}
	})

	t.Run("closes when the handshake runs long", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()

		g := &ccsGuard{Conn: server, policy: ccsPolicy{Mechanism: ccsTimeout, Timeout: 50 * time.Millisecond}}
		g.timer = time.AfterFunc(g.policy.Timeout, g.trip)

		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(ccsRecord); err == nil {
			// The first write may land before the timer fires; the point is
			// that the connection dies shortly after, without a reply.
			time.Sleep(150 * time.Millisecond)
		}
		if _, err := g.Read(make([]byte, 8)); err == nil {
			t.Fatal("the guard kept reading past its deadline")
		}
	})

	t.Run("a completed handshake disarms it", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		g := newCCSGuard(server, "sberbank.ru")
		g.handshakeDone()

		g.mu.Lock()
		armed := g.timer != nil
		g.mu.Unlock()
		if armed {
			t.Fatal("the deadline is still armed after the handshake finished")
		}
	})
}

// TestCCSGuardStopsAfterHandshake pins the requirement that counting ends with
// the handshake. Past that everything is ApplicationData, where a 0x14 is just
// a byte of ciphertext, and a connection carrying enough traffic would
// otherwise eventually kill itself.
func TestCCSGuardStopsAfterHandshake(t *testing.T) {
	t.Parallel()

	// An ApplicationData record whose body is full of 0x14 bytes.
	body := make([]byte, 512)
	for i := range body {
		body[i] = 0x14
	}
	rec := append([]byte{0x17, 0x03, 0x03, 0x02, 0x00}, body...)
	stream := repeat(rec, 200)

	g := newCCSGuard(&scriptConn{data: stream}, "yandex.ru")
	g.handshakeDone()

	if _, err := feedGuard(t, g, stream, 1024); err != nil {
		t.Fatalf("application data tripped the guard: %v", err)
	}
}

// TestCCSGuardCountsRecordsNotBytes checks the parser skips record bodies. A
// 0x14 inside a body is data, not a record, and a guard that cannot tell the
// difference would cut ordinary connections.
func TestCCSGuardCountsRecordsNotBytes(t *testing.T) {
	t.Parallel()

	body := make([]byte, 300)
	for i := range body {
		body[i] = 0x14
	}
	handshakeRec := append([]byte{0x16, 0x03, 0x03, 0x01, 0x2c}, body...)
	stream := append(append([]byte{}, handshakeRec...), repeat(ccsRecord, 3)...)

	g := newCCSGuard(&scriptConn{data: stream}, "yandex.ru")
	if _, err := feedGuard(t, g, stream, 64); err != nil {
		t.Fatalf("a normal handshake record tripped the guard: %v", err)
	}
	g.mu.Lock()
	got := g.count
	g.mu.Unlock()
	if got != 3 {
		t.Fatalf("counted %d records, want the 3 real ones", got)
	}
}

// TestCCSGuardSurvivesSplitHeaders feeds the stream a byte at a time. A peer
// chooses how the stream is chopped up, so a guard that assumes whole headers
// arrive together can be walked straight past.
func TestCCSGuardSurvivesSplitHeaders(t *testing.T) {
	t.Parallel()

	stream := repeat(ccsRecord, 40)
	g := newCCSGuard(&scriptConn{data: stream, chunk: 1}, "yandex.ru")
	if _, err := feedGuard(t, g, stream, 1); !errors.Is(err, errCCSFlood) {
		t.Fatalf("err = %v, want errCCSFlood even when headers are split", err)
	}
}

// TestCCSGuardOrdinaryClientUntouched is the one that matters for users: a real
// client sends exactly one ChangeCipherSpec, and it must be invisible to this.
func TestCCSGuardOrdinaryClientUntouched(t *testing.T) {
	t.Parallel()

	for sni := range donorProfiles {
		g := newCCSGuard(&scriptConn{data: ccsRecord}, sni)
		if _, err := feedGuard(t, g, ccsRecord, 16); err != nil {
			t.Fatalf("%s: a single ChangeCipherSpec was rejected: %v", sni, err)
		}
	}
}

func TestDefaultCCSPolicyIsNotAnOutlier(t *testing.T) {
	t.Parallel()

	// The default has to sit inside the range of measured TLS 1.3 donors. Below
	// them we would be the host that dies first, which is a signal; above them
	// we would be the host that endures longest, which is the same signal.
	lo, hi := 0, 0
	for sni, prof := range donorProfiles {
		if prof.CCS.Mechanism != ccsCount || sni == "mail.ru" {
			continue // mail.ru is TLS 1.2; see defaultCCSPolicy
		}
		if lo == 0 || prof.CCS.Limit < lo {
			lo = prof.CCS.Limit
		}
		if prof.CCS.Limit > hi {
			hi = prof.CCS.Limit
		}
	}
	if defaultCCSPolicy.Limit < lo || defaultCCSPolicy.Limit > hi {
		t.Fatalf("default limit %d is outside the measured range %d..%d",
			defaultCCSPolicy.Limit, lo, hi)
	}
}

// --- CI guards -------------------------------------------------------------

// donorsWithoutMeasurement are pool members running on the default rather than
// on a measurement, each with the reason.
//
// Writing them down is the point. A donor that quietly falls back to the
// default is a donor running on a guess nobody remembers making, so a new one
// fails the test below until someone either measures it or records why not.
var donorsWithoutMeasurement = map[string]string{
	// The probe host reaches these through tiredvpn0, so it would measure our
	// own tunnel rather than the donor.
	"github.com":                    "routes through tiredvpn0 from the measuring host",
	"api.github.com":                "routes through tiredvpn0 from the measuring host",
	"raw.githubusercontent.com":     "routes through tiredvpn0 from the measuring host",
	"objects.githubusercontent.com": "routes through tiredvpn0 from the measuring host",

	// In the SNI whitelist but outside the donor set REALITY actually draws
	// from: derivePool picks the developer category and the fallback is the
	// static Russian list, and none of these are in either. Measure them before
	// they are ever put in the donor pool.
	"yandex.net": "in the whitelist, not in the REALITY donor pool",
	"vk.me":      "in the whitelist, not in the REALITY donor pool",
	"ok.ru":      "in the whitelist, not in the REALITY donor pool",
	"mos.ru":     "in the whitelist, not in the REALITY donor pool",
}

// realityDonorPool is the set of names REALITY can present itself as: the
// developer category derivePool draws from, plus the Russian and banking names
// that make up the static fallback. Those are the SNIs whose tolerance we may
// be asked to imitate, and so the ones the table has to cover.
func realityDonorPool() map[string]bool {
	pool := map[string]bool{}
	for _, e := range evasion.WhitelistedSNIs {
		switch e.Category {
		case "developer", "russian", "banking":
			pool[e.SNI] = true
		}
	}
	return pool
}

// TestEveryPoolDonorHasACCSEntry fails, by name, on a donor we might imitate
// without a measurement behind it. Adding donors is easy and measuring them is
// not, so without this the table quietly covers less of the pool every release.
func TestEveryPoolDonorHasACCSEntry(t *testing.T) {
	t.Parallel()

	var unbacked []string
	for sni := range realityDonorPool() {
		p, ok := donorProfiles[sni]
		measured := ok && p.CCS.Mechanism != ccsUnmeasured
		if measured {
			continue
		}
		if _, excused := donorsWithoutMeasurement[sni]; !excused {
			unbacked = append(unbacked, sni)
		}
	}
	slices.Sort(unbacked)

	if len(unbacked) > 0 {
		t.Fatalf("donors we may imitate with no ChangeCipherSpec measurement: %v\n"+
			"measure them and run go generate ./internal/server/, or add them to "+
			"donorsWithoutMeasurement with the reason", unbacked)
	}
}

// TestUnmeasuredDonorsFallBackDeliberately pins what happens to a name with no
// measurement, including the cover hosts other strategies use, which the donor
// probe never covered.
func TestUnmeasuredDonorsFallBackDeliberately(t *testing.T) {
	t.Parallel()

	for _, sni := range []string{"github.com", "api.googleapis.com", "www.google.com", "not-a-real-host"} {
		if got := ccsPolicyFor(sni); got != defaultCCSPolicy {
			t.Fatalf("%s: policy = %+v, want the default %+v", sni, got, defaultCCSPolicy)
		}
	}
}

// TestCCSTableIsFresh fails once the measurements are old enough to be fiction.
// Sites change; a table nobody re-measured is worse than no table, because it
// reads like fact.
func TestCCSTableIsFresh(t *testing.T) {
	t.Parallel()

	const maxAge = 90 * 24 * time.Hour
	if age := time.Since(donorProfilesMeasuredAt); age > maxAge {
		t.Fatalf("the ChangeCipherSpec table was measured %d days ago (limit %d): re-run the probe "+
			"and regenerate with go generate ./internal/server/",
			int(age.Hours()/24), int(maxAge.Hours()/24))
	}
}

// --- helpers ---------------------------------------------------------------

func repeat(b []byte, n int) []byte {
	out := make([]byte, 0, len(b)*n)
	for range n {
		out = append(out, b...)
	}
	return out
}

// scriptConn replays a fixed stream. chunk caps how much a single Read returns,
// so a test can force records to straddle read boundaries.
type scriptConn struct {
	data  []byte
	pos   int
	chunk int
}

func (c *scriptConn) Read(b []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	if c.chunk > 0 && len(b) > c.chunk {
		b = b[:c.chunk]
	}
	n := copy(b, c.data[c.pos:])
	c.pos += n
	return n, nil
}
func (c *scriptConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }
