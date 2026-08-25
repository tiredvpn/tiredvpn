package strategy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/detect"
)

// baselineFlows are the six flows nDPI caught in
// test-logs/detectability-baseline-2026-08-24.md, section 2.2. Bytes are already
// net of the 24-byte TLS-in-TLS overhead, exactly as nDPI reports them.
var baselineFlows = [][4]uint32{
	{530, 4096, 267, 661},
	{530, 3767, 251, 78},
	{530, 3348, 200, 1242},
	{530, 3110, 247, 235},
	{530, 2833, 281, 588},
	{530, 2833, 281, 557},
}

// reshapedBursts rewrites a measured four-gram the way the exchange rewrites the
// wire: the server's flight (burst 2) is preceded by a nudge and an ack, so the
// sequence becomes client-burst, nudge, ack, flight, and the rest follows.
func reshapedBursts(flow [4]uint32, nudge, ack uint32) []detect.Burst {
	return []detect.Burst{
		{ToServer: true, Bytes: flow[0], Pkts: 1},
		{ToServer: false, Bytes: nudge, Pkts: 1},
		{ToServer: true, Bytes: ack, Pkts: 1},
		{ToServer: false, Bytes: flow[1], Pkts: 3},
		{ToServer: true, Bytes: flow[2], Pkts: 1},
		{ToServer: false, Bytes: flow[3], Pkts: 1},
	}
}

// TestReshapedFlowsClearAllModels is the acceptance criterion: after reshaping,
// every window of every baseline flow must sit at least RequiredMargin away from
// every model. The nudge and ack sweep their whole jitter range, because the
// sizes are picked per stream and the worst corner is what matters.
func TestReshapedFlowsClearAllModels(t *testing.T) {
	worst := detect.MarginClear
	var worstDesc string

	for _, flow := range baselineFlows {
		for nudge := uint32(reshapeNudgeMin); nudge <= reshapeNudgeMax; nudge++ {
			ack := uint32(reshapeAckLen)
			bursts := detect.Merge(reshapedBursts(flow, nudge, ack))
			windows := detect.Windows(bursts)
			if len(windows) == 0 {
				t.Fatalf("flow %v nudge %d: no windows produced", flow, nudge)
			}
			for i, w := range windows {
				m := detect.Margin(w)
				if m < worst {
					worst = m
					worstDesc = fmt.Sprintf("flow %v nudge %d ack %d window %d bytes %v",
						flow, nudge, ack, i, w.Bytes())
				}
			}
		}
	}

	if worst < detect.RequiredMargin {
		t.Errorf("worst margin %.3f < required %.3f (%s)", worst, detect.RequiredMargin, worstDesc)
	}
	t.Logf("worst margin across all flows and all jitter: %.3f (%s)", worst, worstDesc)
}

// TestUnreshapedFlowsAreCaught is the control: without the exchange the same six
// flows must still be caught, otherwise the test above proves nothing.
func TestUnreshapedFlowsAreCaught(t *testing.T) {
	for _, flow := range baselineFlows {
		bursts := []detect.Burst{
			{ToServer: true, Bytes: flow[0], Pkts: 1},
			{ToServer: false, Bytes: flow[1], Pkts: 3},
			{ToServer: true, Bytes: flow[2], Pkts: 1},
			{ToServer: false, Bytes: flow[3], Pkts: 1},
		}
		windows := detect.Windows(detect.Merge(bursts))
		if len(windows) != 1 {
			t.Fatalf("flow %v: expected 1 window, got %d", flow, len(windows))
		}
		caught, model := detect.Caught(windows[0])
		if !caught {
			t.Errorf("flow %v: baseline says nDPI caught this, model says clear", flow)
			continue
		}
		t.Logf("flow %v caught by %s, margin %.3f", flow, model, detect.Margin(windows[0]))
	}
}

// ---------------------------------------------------------------------------
// plumbing for the wire-level tests
// ---------------------------------------------------------------------------

// writeLog records what was written and when, so ordering between the nudge, the
// ack and the released reply can be asserted.
type writeLog struct {
	mu      sync.Mutex
	entries []logEntry
}

type logEntry struct {
	dir  string // "s->c" or "c->s"
	n    int
	when time.Time
}

// begin records a write that is about to be handed to the pipe and returns its
// index, so the byte count can be corrected once the write returns.
//
// The order has to be taken here rather than on return. net.Pipe.Write returns
// only once the peer has taken the bytes, and the peer may answer immediately -
// the reshaping client writes its ack from inside the Read that received the
// nudge. Recording on return therefore captures the order the two goroutines
// happened to be rescheduled in, not the order of the wire, and the nudge and
// the ack swap places under it: measured at 10 reorderings in 3000 runs at
// -cpu=4, with the order writes were issued in violated 0 times out of 3000.
func (w *writeLog) begin(dir string, n int) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, logEntry{dir: dir, n: n, when: time.Now()})
	return len(w.entries) - 1
}

// finish replaces the recorded length with what the write actually reported, so
// the entry carries the real byte count and not just the requested one.
func (w *writeLog) finish(i, n int) {
	w.mu.Lock()
	w.entries[i].n = n
	w.mu.Unlock()
}

func (w *writeLog) snapshot() []logEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]logEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

// loggingConn wraps one end of a net.Pipe and records writes.
type loggingConn struct {
	net.Conn
	dir string
	log *writeLog
}

func (c *loggingConn) Write(p []byte) (int, error) {
	i := c.log.begin(c.dir, len(p))
	n, err := c.Conn.Write(p)
	c.log.finish(i, n)
	return n, err
}

// newPair returns a server-side and client-side conn over net.Pipe, both logging
// into the same log. net.Pipe is synchronous and unbuffered, which is what we
// want here: it makes ordering violations show up as deadlocks rather than
// hiding behind kernel buffers.
//
// # WHAT THESE TESTS CANNOT SEE, BY CONSTRUCTION
//
// A net.Pipe carries nothing but what the test writes into it. A real tunnel
// stream does not start empty: it opens with this tunnel's own control
// preamble - the client sends a mode byte and a length-prefixed target address,
// the server answers with a one-byte success ack - and only then is there any
// application payload. None of that exists here.
//
// So every test in this file starts the exchange at a boundary the production
// code does not have, and any defect that comes from wrapping the wrong side of
// that boundary is invisible to all of them. That is not hypothetical: the
// first version of this file passed every test below while the reshaper, wired
// around the whole stream, mistook the server's one-byte mode read for the
// client's first application burst and held the success ack behind a nudge.
// Every connection failed with "server rejected target connection", and nothing
// here went red.
//
// The consequence for anyone extending this file: adding a case here does not
// extend coverage to where the wrapper is attached, only to what it does once
// attached. Wiring is verified end to end - a real client against a real server
// with -burst-reshape=on, see test-logs/reshape-e2e/stand.sh in the research
// repository - and there is no way to move that check into this file.
func newPair(l *writeLog) (srv net.Conn, cli net.Conn) {
	a, b := net.Pipe()
	return &loggingConn{Conn: a, dir: "s->c", log: l}, &loggingConn{Conn: b, dir: "c->s", log: l}
}

// ---------------------------------------------------------------------------
// wire-level tests
// ---------------------------------------------------------------------------

// TestExchangeSplitsTheFlight is the merge test: the nudge and the real reply
// must not end up in one burst, so an inbound ack has to be recorded between the
// two outbound writes.
func TestExchangeSplitsTheFlight(t *testing.T) {
	resetBurstReshapeStats()
	l := &writeLog{}
	srvRaw, cliRaw := newPair(l)
	cfg := BurstReshapeConfig{Enabled: true}

	srv := ReshapeServerStream(srvRaw, cfg)
	cli := ReshapeClientStream(cliRaw, cfg)

	reply := bytes.Repeat([]byte{0xAB}, 2833)
	clientHello := bytes.Repeat([]byte{0x16}, 530)

	var wg sync.WaitGroup
	wg.Add(1)
	got := make([]byte, 0, len(reply))
	var readErr error
	go func() {
		defer wg.Done()
		if _, err := cli.Write(clientHello); err != nil {
			readErr = err
			return
		}
		buf := make([]byte, 4096)
		for len(got) < len(reply) {
			n, err := cli.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				readErr = err
				return
			}
		}
	}()

	hello := make([]byte, 4096)
	n, err := srv.Read(hello)
	if err != nil {
		t.Fatalf("server read of client burst: %v", err)
	}
	if n != len(clientHello) {
		t.Fatalf("client burst: got %d bytes, want %d", n, len(clientHello))
	}

	// Drain the client's ack on the server read path; the exchange needs this
	// side to be reading, exactly as the real proxy loop is.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		_, _ = srv.Read(buf)
	}()

	if _, err := srv.Write(reply); err != nil {
		t.Fatalf("server write of reply: %v", err)
	}
	wg.Wait()

	if readErr != nil && !errors.Is(readErr, io.EOF) {
		t.Fatalf("client: %v", readErr)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("client got %d bytes, want %d identical", len(got), len(reply))
	}

	entries := l.snapshot()
	// Expected order: c->s hello, s->c nudge, c->s ack, s->c reply.
	//
	// The position of an entry is the position of the write on the wire, and
	// that is a property of the mechanism rather than of scheduling: the client
	// writes its ack from inside the Read that received the nudge, so the ack
	// cannot be issued before the nudge, and the server writes the reply only
	// after the ack arrives. What is NOT guaranteed - and what this used to
	// assert by accident - is anything about the order the writes *return* in.
	// See writeLog.begin.
	var order []string
	for _, e := range entries {
		order = append(order, fmt.Sprintf("%s:%d", e.dir, e.n))
	}
	if len(entries) < 4 {
		t.Fatalf("expected at least 4 writes, got %v", order)
	}
	nudge := entries[1]
	ack := entries[2]
	reply2 := entries[3]

	if nudge.dir != "s->c" {
		t.Errorf("second write should come from the server, got %v", order)
	}
	if nudge.n < reshapeNudgeMin || nudge.n > reshapeNudgeMax {
		t.Errorf("nudge length %d outside [%d,%d], got %v", nudge.n, reshapeNudgeMin, reshapeNudgeMax, order)
	}
	if ack.dir != "c->s" {
		t.Errorf("third write should come from the client, got %v", order)
	}
	if ack.n != reshapeAckLen {
		t.Errorf("ack length %d, want the fixed %d, got %v", ack.n, reshapeAckLen, order)
	}
	if reply2.dir != "s->c" || reply2.n != len(reply) {
		t.Errorf("fourth write should be the held reply of %d bytes, got %v", len(reply), order)
	}
	// Redundant with the positions above while the recorder is honest, and the
	// check that goes red first if it stops being: a reordered recorder puts the
	// ack's timestamp strictly before the nudge's. Not strict, so two writes
	// landing on the same clock reading cannot fail it.
	if ack.when.Before(nudge.when) {
		t.Errorf("ack was recorded before the nudge")
	}

	// The drain goroutine is parked in Read, which is correct: there is nothing
	// more to read. Close the pipe so it returns before we look at the gauges.
	srvRaw.Close()
	cliRaw.Close()
	<-drained

	st := ReadBurstReshapeStats()
	if st.ReshapedTotal != 1 {
		t.Errorf("reshaped_total = %d, want 1", st.ReshapedTotal)
	}
	if st.HoldBytes != 0 || st.HoldStreams != 0 {
		t.Errorf("gauges not drained: hold_bytes=%d hold_streams=%d", st.HoldBytes, st.HoldStreams)
	}
}

// TestHoldCapReleasesImmediately covers the 16 KiB ceiling: a 32 KiB reply goes
// out without waiting for any ack.
func TestHoldCapReleasesImmediately(t *testing.T) {
	resetBurstReshapeStats()
	l := &writeLog{}
	srvRaw, cliRaw := newPair(l)
	srv := ReshapeServerStream(srvRaw, BurstReshapeConfig{Enabled: true})

	reply := bytes.Repeat([]byte{0xCD}, 32<<10)

	// A client that never acks, only reads.
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 64<<10)
		total := 0
		for total < len(reply) {
			n, err := cliRaw.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		got <- total
	}()

	// Feed the client burst so the exchange is armed.
	go func() { _, _ = cliRaw.Write(bytes.Repeat([]byte{0x16}, 530)) }()
	buf := make([]byte, 4096)
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}

	start := time.Now()
	if _, err := srv.Write(reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	elapsed := time.Since(start)

	select {
	case total := <-got:
		if total < len(reply) {
			t.Errorf("client got %d bytes, want %d", total, len(reply))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received the reply")
	}

	if elapsed >= reshapeAckTimeout {
		t.Errorf("oversized reply waited %v; it must not wait for an ack at all", elapsed)
	}
	if st := ReadBurstReshapeStats(); st.SkippedTotal != 1 || st.ReshapedTotal != 0 {
		t.Errorf("expected one skip and no reshape, got %+v", st)
	}
}

// TestAckTimeoutReleases covers the 200 ms bound: a client that never answers
// the nudge still gets its data.
func TestAckTimeoutReleases(t *testing.T) {
	resetBurstReshapeStats()
	l := &writeLog{}
	srvRaw, cliRaw := newPair(l)
	srv := ReshapeServerStream(srvRaw, BurstReshapeConfig{Enabled: true})

	reply := bytes.Repeat([]byte{0xEF}, 1200)
	// A client that reads but never acks: the raw conn is used directly, so no
	// wrapper answers the nudge.
	done := make(chan int, 1)
	go func() {
		buf := make([]byte, 8192)
		total := 0
		for total < len(reply) {
			_ = cliRaw.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := cliRaw.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		done <- total
	}()

	go func() { _, _ = cliRaw.Write(bytes.Repeat([]byte{0x16}, 530)) }()
	buf := make([]byte, 4096)
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}

	start := time.Now()
	if _, err := srv.Write(reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < reshapeAckTimeout {
		t.Errorf("released after %v, expected to wait the full %v", elapsed, reshapeAckTimeout)
	}
	if elapsed > reshapeAckTimeout*3 {
		t.Errorf("released after %v, far beyond the %v bound", elapsed, reshapeAckTimeout)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("client never received the reply")
	}
	if st := ReadBurstReshapeStats(); st.SkippedTotal != 1 {
		t.Errorf("timeout should count as a skip, got %+v", st)
	}
}

// TestCeilingDegradesInsteadOfQueueing covers the global ceiling: past it,
// streams are served unreshaped and nothing blocks.
func TestCeilingDegradesInsteadOfQueueing(t *testing.T) {
	resetBurstReshapeStats()
	// Occupy the only slot there is.
	if !acquireHoldSlot(1) {
		t.Fatal("could not take the first slot")
	}
	defer releaseHoldSlot()

	l := &writeLog{}
	srvRaw, cliRaw := newPair(l)
	srv := ReshapeServerStream(srvRaw, BurstReshapeConfig{Enabled: true, MaxHoldStreams: 1})

	reply := bytes.Repeat([]byte{0x11}, 900)
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := cliRaw.Read(buf)
		got <- n
	}()

	go func() { _, _ = cliRaw.Write(bytes.Repeat([]byte{0x16}, 530)) }()
	buf := make([]byte, 4096)
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}

	start := time.Now()
	if _, err := srv.Write(reply); err != nil {
		t.Fatalf("server write at the ceiling: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= reshapeAckTimeout {
		t.Errorf("at the ceiling the write waited %v; it must not wait at all", elapsed)
	}

	select {
	case n := <-got:
		if n != len(reply) {
			t.Errorf("client got %d bytes, want %d - the reply must be unreshaped, not prefixed", n, len(reply))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client never received the reply")
	}
	if st := ReadBurstReshapeStats(); st.SkippedTotal != 1 || st.ReshapedTotal != 0 {
		t.Errorf("expected one skip at the ceiling, got %+v", st)
	}
}

// TestDisabledIsUntouched: with the feature off the wrappers must return the
// stream itself, so there is nothing in the data path at all.
func TestDisabledIsUntouched(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := ReshapeServerStream(a, BurstReshapeConfig{}); got != a {
		t.Error("server: disabled must return the original conn")
	}
	if got := ReshapeClientStream(b, BurstReshapeConfig{}); got != b {
		t.Error("client: disabled must return the original conn")
	}
}

// TestClientIgnoresNonNudge is the one-sided guard: a server that is not
// reshaping sends its reply straight away, and a reshaping client must pass it
// through rather than eat the head of it. The guard is positional and only works
// when the reply falls outside the nudge size range - see the package comment.
func TestClientIgnoresNonNudge(t *testing.T) {
	l := &writeLog{}
	srvRaw, cliRaw := newPair(l)
	cli := ReshapeClientStream(cliRaw, BurstReshapeConfig{Enabled: true})

	reply := bytes.Repeat([]byte{0x77}, 1400)
	go func() {
		_, _ = srvRaw.Read(make([]byte, 4096))
		_, _ = srvRaw.Write(reply)
	}()

	if _, err := cli.Write(bytes.Repeat([]byte{0x16}, 530)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := cli.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("client read: %v", err)
	}
	if n != len(reply) {
		t.Fatalf("client got %d bytes, want the whole %d-byte reply untouched", n, len(reply))
	}
}

// TestConcurrentStreamsStayBounded is the load test, scaled to something a unit
// test can run: 500 concurrent streams, held bytes never above the per-stream
// cap times the ceiling, and no monotonic growth in heap over the run.
func TestConcurrentStreamsStayBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("load test skipped in -short")
	}
	resetBurstReshapeStats()

	const streams = 500
	const ceiling = 64

	var peakHoldBytes int64
	var peakHoldStreams int64
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			st := ReadBurstReshapeStats()
			if st.HoldBytes > atomic.LoadInt64(&peakHoldBytes) {
				atomic.StoreInt64(&peakHoldBytes, st.HoldBytes)
			}
			if st.HoldStreams > atomic.LoadInt64(&peakHoldStreams) {
				atomic.StoreInt64(&peakHoldStreams, st.HoldStreams)
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	reply := bytes.Repeat([]byte{0x5A}, 2833)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := &writeLog{}
			srvRaw, cliRaw := newPair(l)
			cfg := BurstReshapeConfig{Enabled: true, MaxHoldStreams: ceiling}
			srv := ReshapeServerStream(srvRaw, cfg)
			cli := ReshapeClientStream(cliRaw, cfg)
			defer srvRaw.Close()
			defer cliRaw.Close()

			var inner sync.WaitGroup
			inner.Add(1)
			go func() {
				defer inner.Done()
				_, _ = cli.Write(bytes.Repeat([]byte{0x16}, 530))
				buf := make([]byte, 8192)
				total := 0
				for total < len(reply) {
					_ = cliRaw.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := cli.Read(buf)
					total += n
					if err != nil {
						return
					}
				}
			}()

			buf := make([]byte, 4096)
			_ = srvRaw.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := srv.Read(buf); err != nil {
				inner.Wait()
				return
			}
			go func() {
				b := make([]byte, 4096)
				_ = srvRaw.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = srv.Read(b)
			}()
			_ = srvRaw.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = srv.Write(reply)
			inner.Wait()
		}()
	}
	wg.Wait()
	close(stop)
	watcher.Wait()

	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)

	maxHold := int64(ceiling) * reshapeHoldCap
	if got := atomic.LoadInt64(&peakHoldBytes); got > maxHold {
		t.Errorf("peak hold_bytes %d exceeds ceiling*cap %d", got, maxHold)
	}
	if got := atomic.LoadInt64(&peakHoldStreams); got > ceiling {
		t.Errorf("peak hold_streams %d exceeds ceiling %d", got, ceiling)
	}
	st := ReadBurstReshapeStats()
	if st.HoldBytes != 0 || st.HoldStreams != 0 {
		t.Errorf("gauges not drained after the run: %+v", st)
	}
	if st.ReshapedTotal+st.SkippedTotal == 0 {
		t.Error("no stream went through the exchange at all")
	}
	t.Logf("peak hold: %d bytes across %d streams; totals %+v; heap %d -> %d",
		peakHoldBytes, peakHoldStreams, st, before.HeapAlloc, after.HeapAlloc)
}

// TestNudgeLenInRange checks the jitter never leaves the measured optimum.
func TestNudgeLenInRange(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 2000; i++ {
		n := reshapeRandomLen(reshapeNudgeMin, reshapeNudgeMax-reshapeNudgeMin)
		if n < reshapeNudgeMin || n >= reshapeNudgeMax {
			t.Fatalf("nudge length %d outside [%d,%d)", n, reshapeNudgeMin, reshapeNudgeMax)
		}
		seen[n] = true
	}
	if len(seen) < 10 {
		t.Errorf("jitter looks degenerate: only %d distinct lengths in 2000 draws", len(seen))
	}
}

// TestNudgeRangeClearsTheBarOnThePlainPath checks the shipped range against the
// path our production traffic actually takes. It is deliberately not an
// optimisation test any more: the range is picked to work on BOTH paths, and
// the other one cannot be exercised from these baseline vectors because it
// subtracts 24 bytes per packet and starts counting only after a
// ChangeCipherSpec, which our framing does not send. See
// internal/detect/mode.go.
//
// So this pins the weaker of the two constraints. The stronger one - ack 40
// rather than a jittered 40-65 - comes from the tls-in-tls path and is recorded
// in the constant's comment, not here.
func TestNudgeRangeClearsTheBarOnThePlainPath(t *testing.T) {
	worst, at := detect.MarginClear, 0
	for n := reshapeNudgeMin; n <= reshapeNudgeMax; n++ {
		for _, flow := range baselineFlows {
			bursts := detect.Merge(reshapedBursts(flow, uint32(n), uint32(reshapeAckLen)))
			for _, w := range detect.Windows(bursts) {
				if m := detect.Margin(w); m < worst {
					worst, at = m, n
				}
			}
		}
	}
	t.Logf("range %d..%d with ack %d -> worst margin %.3f on the plain path (binds at nudge=%d)",
		reshapeNudgeMin, reshapeNudgeMax, reshapeAckLen, worst, at)
	if worst < detect.RequiredMargin {
		t.Errorf("worst margin %.3f < required %.3f", worst, detect.RequiredMargin)
	}
}

func TestAckLengthIsFixed(t *testing.T) {
	if reshapeAckLen < 30 || reshapeAckLen > 65 {
		t.Errorf("ack %d outside the range the model was swept over", reshapeAckLen)
	}
}
