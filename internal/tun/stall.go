package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// Stall detection: a session that is alive but useless.
//
// The tunnel can stay up while nothing gets through it: a per-flow byte cap
// on the route (the TSPU #490 pattern), a policer, a one-way blackhole. HTTP
// Polling never notices - its own keepalive feeder keeps the read deadline fed
// - and REALITY and Geneva notice a partial freeze only when it turns total.
// The signal measured on the stand (test-logs/degraded-2026-10-22) is the
// stalled flow: the application sent data (a TCP segment with payload, or a
// FIN) into a flow that recently got answers, and nothing came back down in
// that flow for the threshold. It is read entirely inside the client, off
// the packets it moves between the TUN and the tunnel.
//
// On the stand no healthy load crossed 0.58 s and an honestly slow 256 kbit/s
// link with a download crossed 19.6 s; every "data does not flow" fault
// crossed 30 s within 29.4-32.6 s. A dead application peer behind a healthy
// tunnel crosses too, which is why a crossing is only a suspicion: it is
// confirmed by keepalive echoes (stallMonitor.confirm).
// stallClockSet is the detector's clocks.
type stallClockSet struct {
	// threshold is T: how long the oldest demand may wait for an answer in
	// its flow before the session is suspected.
	threshold time.Duration
	// echoWait is how long one confirming keepalive waits for its echo.
	echoWait time.Duration
	// checkEvery is how often a session is checked; local only.
	checkEvery time.Duration
	// pause is the wait between the two confirming keepalives: uniform
	// 1-3 s. No measured distribution to match; it only keeps the pair from
	// a fixed spacing.
	pause func() time.Duration
}

// stallClocksNow holds the clocks in force. Tests swap in shorter ones;
// atomic, because relays of other tests may still be reading.
var stallClocksNow atomic.Pointer[stallClockSet]

func init() {
	stallClocksNow.Store(&stallClockSet{
		threshold:  30 * time.Second,
		echoWait:   3 * time.Second,
		checkEvery: time.Second,
		pause:      func() time.Duration { return time.Second + rand.N(2*time.Second) },
	})
}

func stallClocks() *stallClockSet { return stallClocksNow.Load() }

const (
	// stallFlowFresh is how recent a flow's last answer must be for new
	// demand in it to count: a flow silent for longer may simply be over.
	stallFlowFresh = 60 * time.Second
	// stallMaxFlows bounds the flow table.
	stallMaxFlows = 1024
)

// tcpSegment is what the detector reads off one IP packet.
type tcpSegment struct {
	src, dst netip.AddrPort
	syn      bool
	fin      bool
	rst      bool
	payload  int // TCP payload length, from the IP and TCP headers
	window   uint16
}

// parseTCPSegment reads a TCP segment out of an IPv4 or IPv6 packet. IPv4
// fragments and IPv6 packets with extension headers are not read: the first
// can not be told apart from a whole segment by length, the second is rare
// enough on a TUN not to be worth the walk. Lengths come from the headers, so
// a capture cut short after the TCP header still parses.
func parseTCPSegment(pkt []byte) (tcpSegment, bool) {
	if len(pkt) < 1 {
		return tcpSegment{}, false
	}
	var src, dst netip.Addr
	var ipHdr, ipTotal int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return tcpSegment{}, false
		}
		ipHdr = int(pkt[0]&0x0f) * 4
		ipTotal = int(binary.BigEndian.Uint16(pkt[2:4]))
		frag := binary.BigEndian.Uint16(pkt[6:8])
		if ipHdr < 20 || pkt[9] != 6 || frag&0x3fff != 0 {
			return tcpSegment{}, false
		}
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	case 6:
		if len(pkt) < 40 || pkt[6] != 6 {
			return tcpSegment{}, false
		}
		ipHdr = 40
		ipTotal = 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
	default:
		return tcpSegment{}, false
	}
	if len(pkt) < ipHdr+20 {
		return tcpSegment{}, false
	}
	t := pkt[ipHdr:]
	tcpHdr := int(t[12]>>4) * 4
	if tcpHdr < 20 || ipTotal < ipHdr+tcpHdr {
		return tcpSegment{}, false
	}
	flags := t[13]
	return tcpSegment{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(t[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(t[2:4])),
		fin:     flags&0x01 != 0,
		syn:     flags&0x02 != 0,
		rst:     flags&0x04 != 0,
		payload: ipTotal - ipHdr - tcpHdr,
		window:  binary.BigEndian.Uint16(t[14:16]),
	}, true
}

// flowKey names one TCP flow from the client's side.
type flowKey struct {
	local, remote netip.AddrPort
}

// flowState is what the detector keeps per flow.
type flowState struct {
	lastDown     time.Time // the last packet that came down in this flow
	pendingSince time.Time // the first demand still waiting for an answer
	ignored      bool      // confirmed alive while pending: wait for its answer
	zeroWindow   bool      // the peer's last packet closed its window
}

// flowTable follows the session's TCP flows. Safe for concurrent use: the
// TUN reader, the tunnel reader and the monitor each touch it.
type flowTable struct {
	mu    sync.Mutex
	flows map[flowKey]*flowState
}

func newFlowTable() *flowTable {
	return &flowTable{flows: make(map[flowKey]*flowState)}
}

// down books a packet the tunnel delivered into the TUN. Only here is a flow
// created: a flow is worth watching once it has been answered.
func (t *flowTable) down(pkt []byte, now time.Time) {
	if t == nil {
		return
	}
	seg, ok := parseTCPSegment(pkt)
	if !ok {
		return
	}
	key := flowKey{local: seg.dst, remote: seg.src}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flows == nil {
		t.flows = make(map[flowKey]*flowState)
	}
	f := t.flows[key]
	if f == nil {
		if len(t.flows) >= stallMaxFlows {
			t.evictLocked(now)
		}
		f = &flowState{}
		t.flows[key] = f
	}
	f.lastDown = now
	f.pendingSince = time.Time{}
	f.ignored = false
	f.zeroWindow = seg.window == 0 && !seg.syn && !seg.rst
}

// up books a packet the application sent into the tunnel. Demand is payload
// or a FIN in a flow answered within stallFlowFresh. A bare ACK, a SYN, a RST
// and a window probe into a closed window ask nothing of the peer.
func (t *flowTable) up(pkt []byte, now time.Time) {
	if t == nil {
		return
	}
	seg, ok := parseTCPSegment(pkt)
	if !ok || seg.syn || seg.rst || (seg.payload == 0 && !seg.fin) {
		return
	}
	key := flowKey{local: seg.src, remote: seg.dst}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	if f == nil || f.ignored || !f.pendingSince.IsZero() || now.Sub(f.lastDown) > stallFlowFresh {
		return
	}
	if f.zeroWindow && seg.payload <= 1 && !seg.fin {
		return
	}
	f.pendingSince = now
}

// evictLocked makes room: flows with nothing pending and no answer within
// stallFlowFresh go first; if that frees nothing, the idle flow answered
// longest ago, and only in a table full of waiting flows a waiting one.
func (t *flowTable) evictLocked(now time.Time) {
	var idle, busy flowKey
	var idleAt, busyAt time.Time
	for k, f := range t.flows {
		switch {
		case f.pendingSince.IsZero() && now.Sub(f.lastDown) > stallFlowFresh:
			delete(t.flows, k)
		case f.pendingSince.IsZero():
			if idleAt.IsZero() || f.lastDown.Before(idleAt) {
				idle, idleAt = k, f.lastDown
			}
		default:
			if busyAt.IsZero() || f.lastDown.Before(busyAt) {
				busy, busyAt = k, f.lastDown
			}
		}
	}
	if len(t.flows) < stallMaxFlows {
		return
	}
	if !idleAt.IsZero() {
		delete(t.flows, idle)
		return
	}
	delete(t.flows, busy)
}

// reset forgets every flow: a new tunnel connection starts with none.
func (t *flowTable) reset() {
	t.mu.Lock()
	clear(t.flows)
	t.mu.Unlock()
}

// stalledFor reports how long the oldest demand that is not ignored has been
// waiting, zero when nothing waits.
func (t *flowTable) stalledFor(now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var stall time.Duration
	for _, f := range t.flows {
		if f.ignored || f.pendingSince.IsZero() {
			continue
		}
		stall = max(stall, now.Sub(f.pendingSince))
	}
	return stall
}

// oldestPending names the flow whose demand has waited longest (not
// ignored), and since when.
func (t *flowTable) oldestPending() (flowKey, time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var key flowKey
	var since time.Time
	for k, f := range t.flows {
		if f.ignored || f.pendingSince.IsZero() {
			continue
		}
		if since.IsZero() || f.pendingSince.Before(since) {
			key, since = k, f.pendingSince
		}
	}
	return key, since, !since.IsZero()
}

// stillPending reports whether key's demand from since is still unanswered.
func (t *flowTable) stillPending(key flowKey, since time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	return f != nil && !f.ignored && f.pendingSince.Equal(since)
}

// ignorePending marks every waiting flow as confirmed alive: the session
// answered a keepalive, so whatever those flows wait for is their peer's
// business (a dead server behind a healthy tunnel). Their next answer clears
// the mark.
func (t *flowTable) ignorePending() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, f := range t.flows {
		if !f.pendingSince.IsZero() {
			f.ignored = true
		}
	}
}

// stallMonitor decides on one session: suspicion from the flow table, then
// confirmation by keepalive echoes.
type stallMonitor struct {
	flows     *flowTable
	threshold time.Duration
	echoWait  time.Duration
	now       func() time.Time
	// pause is the wait between the two confirming keepalives.
	pause func() time.Duration
}

func newStallMonitor(flows *flowTable) *stallMonitor {
	c := stallClocks()
	return &stallMonitor{
		flows:     flows,
		threshold: c.threshold,
		echoWait:  c.echoWait,
		now:       time.Now,
		pause:     c.pause,
	}
}

// suspect reports a stall past the threshold on a session at least as old
// as the threshold.
func (m *stallMonitor) suspect(sessionAge time.Duration) (stalledFlow, bool) {
	if sessionAge < m.threshold {
		return stalledFlow{}, false
	}
	key, since, ok := m.flows.oldestPending()
	if !ok {
		return stalledFlow{}, false
	}
	f := stalledFlow{key: key, since: since, stall: m.now().Sub(since)}
	return f, f.stall >= m.threshold
}

// stalledFlow is the flow a suspicion is about.
type stalledFlow struct {
	key   flowKey
	since time.Time
	stall time.Duration
}

// unanswered reports whether the suspected flow is still waiting for the
// same demand: a verdict on a flow that got its answer during the
// confirmation - its packet queued behind a downlink burst - would end a
// session that works.
func (m *stallMonitor) unanswered(f stalledFlow) bool {
	return m.flows.stillPending(f.key, f.since)
}

// confirm asks the session whether it is alive: a keepalive, a window of
// echoWait, a pause of 1-3 s, a second keepalive and its window. An echo at
// any point of all that counts - the baseline is taken once, before the first
// send, and it is looked for once more after the last window - so an echo
// that came late, during the pause, is not lost. echoes must count only what
// the server really sent - HTTP Polling makes up keepalive frames of its own
// (see strategy.ServerKeepaliveCounter), and counting those passed every
// confirmation.
//
// It reports whether an echo came and how many keepalives went out. A send
// that fails, or a stop, gives err: no answer either way.
func (m *stallMonitor) confirm(stop <-chan struct{}, send func() error, echoes func() uint64) (alive bool, sent int, err error) {
	before := echoes()
	echoed := func() bool {
		if echoes() != before {
			m.flows.ignorePending()
			return true
		}
		return false
	}
	// wait watches for an echo for d; false means stopped.
	wait := func(d time.Duration) (bool, error) {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if echoed() {
				return true, nil
			}
			if !sleepOrStop(stop, min(50*time.Millisecond, time.Until(deadline))) {
				return false, errConfirmStopped
			}
		}
		return false, nil
	}
	for attempt := range 2 {
		if attempt > 0 {
			if ok, err := wait(m.pause()); ok || err != nil {
				return ok, sent, err
			}
		}
		if err := send(); err != nil {
			return false, sent, err
		}
		sent++
		if ok, err := wait(m.echoWait); ok || err != nil {
			return ok, sent, err
		}
	}
	return echoed(), sent, nil
}

// errConfirmStopped: the confirmation ended because its session did.
var errConfirmStopped = errors.New("confirmation stopped")

// sleepOrStop waits d, or less if stop closes; false means stopped.
func sleepOrStop(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-t.C:
		return true
	}
}

// Degraded-session verdicts are limited process-wide: at most
// stallVerdictMax in stallVerdictWindow, after which verdicts are only logged
// for stallVerdictQuiet. A link slower than anything measured (under 256
// kbit/s) could otherwise put the client on a reconnect carousel.
const (
	stallVerdictMax    = 3
	stallVerdictWindow = 10 * time.Minute
	stallVerdictQuiet  = 10 * time.Minute
)

type verdictLimiter struct {
	mu         sync.Mutex
	recent     []time.Time
	quietUntil time.Time
}

// stallVerdictsNow is the process-wide limiter: one process carries one
// tunnel. Atomic so a test can put in a fresh one under running relays.
var stallVerdictsNow atomic.Pointer[verdictLimiter]

func init() { stallVerdictsNow.Store(&verdictLimiter{}) }

func stallVerdicts() *verdictLimiter { return stallVerdictsNow.Load() }

// allow reports whether a verdict at now may be acted on, and books it.
// When it may not, until is when verdicts are acted on again: no session is
// judged before then.
func (l *verdictLimiter) allow(now time.Time) (ok bool, until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.quietUntil) {
		return false, l.quietUntil
	}
	kept := l.recent[:0]
	for _, t := range l.recent {
		if now.Sub(t) < stallVerdictWindow {
			kept = append(kept, t)
		}
	}
	l.recent = kept
	if len(l.recent) >= stallVerdictMax {
		l.quietUntil = now.Add(stallVerdictQuiet)
		l.recent = l.recent[:0]
		return false, l.quietUntil
	}
	l.recent = append(l.recent, now)
	return true, time.Time{}
}

// sessionDegradedError is the reason a session is ended by the stall
// detector. It matches strategy.ErrServerSilent: for the reconnect it is the
// server going quiet - the first reconnect walks the pool through the gate.
type sessionDegradedError struct {
	stall time.Duration
}

func (e *sessionDegradedError) Error() string {
	return fmt.Sprintf("a TCP flow waited %v for an answer and the keepalives went unanswered", e.stall.Round(time.Millisecond))
}

func (e *sessionDegradedError) Is(target error) bool { return target == strategy.ErrServerSilent }

// watchStalls is the stall detector on the desktop tunnel: once a second it
// asks the session's flow table whether demand has waited the threshold, and
// if so confirms with keepalives (stallMonitor). An unanswered confirmation
// ends the session as degraded - at most once per session, and within the
// process-wide verdict limit. Sessions on Android run through the control
// socket's relay, which carries its own (tunRelay.watchStalls).
func (v *VPNClient) watchStalls() {
	var judged net.Conn     // the session that has had its verdict
	var unjudged net.Conn   // the session that can not be judged, logged once
	var holdUntil time.Time // no suspicion before this
	ticker := time.NewTicker(stallClocks().checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-ticker.C:
		}
		if atomic.LoadInt32(&v.running) == 0 {
			return
		}
		v.mu.Lock()
		conn, flows, connectedAt, lastRx, strat := v.conn, v.stall, v.connectedAt, v.lastRx, v.strategy
		v.mu.Unlock()
		if conn == nil || flows == nil || conn == judged || time.Now().Before(holdUntil) {
			continue
		}
		// The table of this conn's session, read with it: a confirmation
		// still running when a swap or a hop replaces the session works on
		// the old table and can not mark the new session's flows.
		mon := newStallMonitor(flows)
		suspect, ok := mon.suspect(time.Since(connectedAt))
		if !ok {
			continue
		}
		echoes := echoSourceFor(conn, strat, v.keepaliveEchoes.Load)
		if !echoes.usable() {
			if unjudged != conn {
				log.Info("Session suspect but not judged: %s", echoes.why)
				unjudged = conn
			}
			continue
		}
		stall := suspect.stall
		log.Info("Session suspect: a flow has waited %v for an answer - confirming with keepalives", stall.Round(time.Millisecond))
		alive, sent, err := mon.confirm(v.stopCh, keepaliveSender(conn, v.stopCh), echoes.count)
		v.mu.Lock()
		current := v.conn == conn
		v.mu.Unlock()
		if !current {
			continue
		}
		if err != nil {
			// No keepalive could go out: no answer either way. Not "alive",
			// which would leave the flows ignored, and no verdict; the
			// session is likely going down on its own. Asked again after
			// one threshold.
			log.Info("Session suspect: could not confirm (%v) - no verdict", err)
			holdUntil = time.Now().Add(mon.threshold)
			continue
		}
		if alive {
			log.Info("Session alive: a keepalive echoed (%d sent); the stalled flow's peer is slow or gone, not the tunnel", sent)
			continue
		}
		if !mon.unanswered(suspect) {
			log.Info("Session alive: the stalled flow got its answer during the confirmation")
			continue
		}
		name := "unknown"
		if strat != nil {
			name = strat.Name()
		}
		if ok, until := stallVerdicts().allow(time.Now()); !ok {
			// Not acting, and not judging: the session is looked at again
			// when verdicts are acted on again - it may still be the useless
			// one then - and no keepalive goes out to confirm in between.
			log.Warn("Session degraded: flow stalled %v, keepalive echo 0/%d (strategy=%s) - not acting until %s, %d verdicts within %v already",
				stall.Round(time.Millisecond), sent, name, until.Format(time.TimeOnly), stallVerdictMax, stallVerdictWindow)
			holdUntil = until
			continue
		}
		judged = conn
		log.Warn("Session degraded: flow stalled %v, keepalive echo 0/%d (strategy=%s, session=%s, last downlink %s ago)",
			stall.Round(time.Millisecond), sent, name, sinceOrUnknown(connectedAt), sinceOrUnknown(lastRx))
		v.connLost(conn, "session degraded", &sessionDegradedError{stall: stall})
	}
}

// echoSource is what a confirmation counts as the server's echo on a conn,
// and whether that count can be had at all.
type echoSource struct {
	count  func() uint64
	usable func() bool
	why    string // when not usable
}

// echoSourceFor reads echoes on conn, carried by strat (nil when unknown):
// the zero-length frames the conn says the server sent, when it makes up its
// own (HTTP Polling), else every zero-length frame read off the tunnel
// (generic). A conn that makes up its own but has lost count - or whose
// count is out of reach under a wrapper - is not judged: the generic count
// includes the made-up frames and would pass every confirmation, and a count
// stuck after lost framing would fail every one.
func echoSourceFor(conn net.Conn, strat strategy.Strategy, generic func() uint64) echoSource {
	if rc, ok := conn.(*replayConn); ok {
		conn = rc.Conn
	}
	if c, ok := strategy.ServerKeepaliveCounterOf(conn); ok {
		return echoSource{
			count:  func() uint64 { n, _ := c.ServerKeepalives(); return n },
			usable: func() bool { _, tracked := c.ServerKeepalives(); return tracked },
			why:    "the conn has lost track of the server's keepalives",
		}
	}
	if km, ok := strat.(strategy.KeepaliveMaker); ok && km.MakesUpKeepalives() {
		return echoSource{count: generic, usable: func() bool { return false },
			why: "the strategy makes up keepalives and their count is out of reach"}
	}
	return echoSource{count: generic, usable: func() bool { return true }}
}

// keepaliveSender writes one zero-length keepalive frame to conn, and returns
// once it is on its way. On HTTP Polling a Write only queues (up to 1 MiB
// ahead of the polls, about 32 s at 256 kbit/s): the send waits until a poll
// has taken the keepalive, so the echo window starts when the server can see
// it, not while it sits behind a bulk upload. Order in the stream is kept -
// the keepalive goes through the queue like everything else. A keepalive
// still queued after stallDeliveryMax is no question asked: an error, so no
// verdict.
func keepaliveSender(conn net.Conn, stop <-chan struct{}) func() error {
	q, queued := uplinkQueue(conn)
	return func() error {
		_ = conn.SetWriteDeadline(time.Now().Add(keepaliveWriteTimeout))
		if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
			return err
		}
		if !queued {
			return nil
		}
		target, _ := q.UplinkProgress()
		deadline := time.Now().Add(stallDeliveryMax)
		for {
			if _, sent := q.UplinkProgress(); sent >= target {
				return nil
			}
			if time.Now().After(deadline) {
				return errKeepaliveQueued
			}
			if !sleepOrStop(stop, 50*time.Millisecond) {
				return errConfirmStopped
			}
		}
	}
}

// stallDeliveryMax bounds the wait for a queued keepalive to go out.
const stallDeliveryMax = time.Minute

var errKeepaliveQueued = errors.New("keepalive still queued behind the uplink")

// uplinkQueue finds the conn's uplink queue, under a replayConn too.
func uplinkQueue(conn net.Conn) (strategy.UplinkQueue, bool) {
	if rc, ok := conn.(*replayConn); ok {
		conn = rc.Conn
	}
	return strategy.UplinkQueueOf(conn)
}

// relayStall is the stall detector's state on the control socket's relay.
type relayStall struct {
	flows  flowTable
	echoes atomic.Uint64 // zero-length frames read off the tunnel
}

// watchStalls is VPNClient.watchStalls for the relay that carries the
// tunnel on Android: same suspicion, same confirmation. On a verdict the
// relay closes the server connection, so its reader ends; OnSessionEnd then
// carries the verdict and OnError a "session_degraded" reason - the app
// reconnects on it as on any dead connection.
func (r *tunRelay) watchStalls() {
	mon := newStallMonitor(&r.stall.flows)
	echoes := echoSourceFor(r.serverConn, nil, r.stall.echoes.Load)
	var unjudgedLogged bool
	var holdUntil time.Time // no suspicion before this
	ticker := time.NewTicker(stallClocks().checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-r.done:
			return
		case <-ticker.C:
		}
		if time.Now().Before(holdUntil) {
			continue
		}
		suspect, ok := mon.suspect(time.Since(r.startedAt))
		if !ok {
			continue
		}
		if !echoes.usable() {
			if !unjudgedLogged {
				log.Info("TUN relay: suspect but not judged: %s", echoes.why)
				unjudgedLogged = true
			}
			continue
		}
		stall := suspect.stall
		log.Info("TUN relay: a flow has waited %v for an answer - confirming with keepalives", stall.Round(time.Millisecond))
		alive, sent, err := mon.confirm(r.stopCh, keepaliveSender(r.serverConn, r.stopCh), echoes.count)
		select {
		case <-r.done:
			return
		default:
		}
		if err != nil && !r.ownerStopped() {
			log.Info("TUN relay: could not confirm (%v) - no verdict", err)
			holdUntil = time.Now().Add(mon.threshold)
			continue
		}
		if alive || r.ownerStopped() {
			if alive {
				log.Info("TUN relay: a keepalive echoed (%d sent); the stalled flow's peer is slow or gone, not the tunnel", sent)
			}
			continue
		}
		if !mon.unanswered(suspect) {
			log.Info("TUN relay: the stalled flow got its answer during the confirmation")
			continue
		}
		if ok, until := stallVerdicts().allow(time.Now()); !ok {
			log.Warn("Session degraded: flow stalled %v, keepalive echo 0/%d - not acting until %s, %d verdicts within %v already",
				stall.Round(time.Millisecond), sent, until.Format(time.TimeOnly), stallVerdictMax, stallVerdictWindow)
			holdUntil = until
			continue
		}
		log.Warn("Session degraded: flow stalled %v, keepalive echo 0/%d (session=%s, last activity %s ago)",
			stall.Round(time.Millisecond), sent, sinceOrUnknown(r.startedAt), r.idleDuration().Round(time.Millisecond))
		r.degraded.Store(&sessionDegradedError{stall: stall})
		r.serverConn.Close()
		return
	}
}

// LocalLinkUp reports whether the client's own link can be confirmed up,
// for a caller outside the package that is about to charge a server.
func LocalLinkUp() bool { return probeLocalLink() }
