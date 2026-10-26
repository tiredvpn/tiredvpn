package tun

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// returnIdleAfter is how long the tunnel must have carried no data, in
// either direction, before the client moves it back to a preferred server.
// A var so tests can shorten it.
//
// The move changes the exit, so the public address the client's traffic
// leaves from and usually the tunnel address: every connection inside the
// tunnel ends, open or not. It is made only when nothing has crossed the
// tunnel for this long. 90 s, not less: a tunnel that is in use but quiet -
// a chat client between polls, a page read between clicks, a video player
// with its buffer full - goes 20-60 s without a packet, and a return in that
// gap breaks what the user is in the middle of. Long-lived connections that
// stay silent longer (an idle SSH session without keepalives) are lost
// anyway; that is the price of the return.
var returnIdleAfter = 90 * time.Second

// returnCheckEvery is how often the client looks whether a return is due.
// The look is local - the selector and two stamps - and puts nothing on the
// wire. A var so tests can shorten it.
var returnCheckEvery = 15 * time.Second

// returnRetryAfter draws how long the client waits after a failed return
// before it tries again; the selector parks a server that fails twice in a
// row on top of it. A var so tests can shorten it.
var returnRetryAfter = func() time.Duration {
	return strategy.HumpDelay(4*time.Minute, 5*time.Minute, 8*time.Minute)
}

// returnDialTimeout bounds the dial of a return. A var so tests can shorten
// it.
var returnDialTimeout = 15 * time.Second

// watchReturnToPreferred runs tryReturnToPreferred every returnCheckEvery
// until the client stops.
func (v *VPNClient) watchReturnToPreferred() {
	t := time.NewTicker(returnCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-t.C:
			v.tryReturnToPreferred()
		}
	}
}

// dataIdleFor is how long the tunnel has carried no data in either
// direction: since the later of the last packet up and the last packet down,
// or since the session began if neither came.
func (v *VPNClient) dataIdleFor() time.Duration {
	v.mu.Lock()
	since := time.Since(v.connectedAt)
	if !v.lastData.IsZero() {
		since = min(since, time.Since(v.lastData))
	}
	v.mu.Unlock()
	if at := v.lastDataTx.Load(); at != 0 {
		since = min(since, time.Duration(monoNow()-at))
	}
	return since
}

// tryReturnToPreferred moves an idle tunnel from a fallback server back to a
// preferred one that is available again, and reports whether it did.
//
// Without it a TUN session went back only on a reconnect boundary
// (endpoint.Selector.Reconsider), and a healthy session on the fallback has
// none: a client that left its primary in a fault stayed on the fallback for
// as long as the session held, hours. A SOCKS client gets a boundary on every
// connection. Now, once the selector says the session has dwelt on the
// fallback for MinDwell and a preferred candidate is out of its park
// (ReturnCandidate), and the tunnel has carried nothing for returnIdleAfter,
// the client dials the preferred candidate with the transport it rides,
// runs the TUN handshake there, and only then installs the new session and
// closes the old one - make before break, as the strategy upgrade does. A
// failed dial or handshake leaves the tunnel where it is; the next try waits
// returnRetryAfter.
//
// Only on an interface the client owns: the new exit hands out other
// addresses, and on Android and macOS the host configures the interface from
// the session it was told about.
func (v *VPNClient) tryReturnToPreferred() bool {
	if !v.ownsInterface || v.manager == nil || atomic.LoadInt32(&v.running) == 0 ||
		atomic.LoadInt32(&v.reconnecting) == 1 || atomic.LoadInt32(&v.portHopInProgress) == 1 {
		return false
	}
	if at := v.returnNotBefore.Load(); at != 0 && monoNow() < at {
		return false
	}
	if v.dataIdleFor() < returnIdleAfter {
		return false
	}
	cand, ok := v.manager.ReturnCandidate()
	if !ok {
		return false
	}
	if !v.upgrading.CompareAndSwap(false, true) {
		return false
	}
	defer v.upgrading.Store(false)

	v.mu.Lock()
	cur, oldConn, localIP := v.strategy, v.conn, v.localIP
	oldCand, hasOldCand := v.sessionCand, v.hasSessionCand
	oldConnectedAt, oldLastRx := v.connectedAt, v.lastRx
	pending := v.upgradePending
	v.mu.Unlock()
	if cur == nil || oldConn == nil || pending != nil || (hasOldCand && oldCand.Addr == cand.Addr) {
		return false
	}

	log.Info("Return: the tunnel has been idle for %v and %s is available again - moving it back from %s",
		v.dataIdleFor().Round(time.Second), cand, oldCand)
	failed := func(why string, err error) bool {
		v.returnNotBefore.Store(monoNow() + int64(returnRetryAfter()))
		log.Info("Return: %s %s (%v), staying on %s", cand, why, err, oldCand)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), returnDialTimeout)
	defer cancel()
	go func() {
		select {
		case <-v.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	conn, err := v.manager.DialReturn(ctx, cur, cand)
	if err != nil {
		return failed("did not connect", err)
	}
	// The dial took up to returnDialTimeout. The handshake registers the
	// session on the exit, and on the same exit - the other family, or two
	// endpoints in front of one exit - that displaces the old one: a tunnel
	// that woke up meanwhile stays where it is, and is left untouched.
	if v.dataIdleFor() < returnIdleAfter {
		conn.Close()
		log.Info("Return: the tunnel carried traffic during the dial, staying on %s", oldCand)
		return false
	}

	if !v.sessionMu.TryLock() {
		// A reconnect or a port hop is mid-handshake.
		conn.Close()
		return false
	}
	resp, n, tunnelConn, err := v.doHandshake(conn, localIP)
	if err != nil {
		v.sessionMu.Unlock()
		conn.Close()
		v.manager.ReturnOutcome(cand, false)
		if !errors.Is(err, errHandshakeNotSent) && !errors.Is(err, errHandshakeRefused) && !v.oldSessionAnswers(oldConn) {
			// The request went out unanswered, and the old session does
			// not answer either: on the same exit the request may have
			// displaced it.
			v.connLost(oldConn, "return to a preferred server", err)
			return false
		}
		return failed("did not answer the handshake", err)
	}
	// A session on the old address displaced the old one on its exit: it is
	// the tunnel now, busy or not (P2-3 of the round-10 review - dropping it
	// left the old one unregistered). On another address the old one still
	// stands, and a tunnel that woke up stays on it.
	sameAddr := net.IP(resp[5:9]).Equal(localIP)
	if !sameAddr && v.dataIdleFor() < returnIdleAfter {
		v.sessionMu.Unlock()
		tunnelConn.Close()
		log.Info("Return: the tunnel carried traffic during the handshake, staying on %s", oldCand)
		return false
	}
	err = v.publishSession(tunnelConn, cur, cand, true, resp, n, oldConn)
	v.sessionMu.Unlock()
	if err != nil {
		log.Info("Return: %v, dropping the session on %s", err, cand)
		return false
	}
	oldConn.Close()
	v.manager.ReturnOutcome(cand, true)
	v.manager.PinCandidate(cand)
	v.manager.SessionEnded(strategy.SessionEnd{Strategy: cur.ID(), Replaced: true,
		Useful: sessionWasUseful(oldConnectedAt, oldLastRx), Endpoint: oldCand, HasEndpoint: hasOldCand})
	log.Info("Return: the tunnel is back on %s", cand)
	// Another exit, maybe another path MTU.
	v.maybeStartMTUProbe(context.Background(), "return")
	return true
}

// returnProbeWait bounds how long oldSessionAnswers waits for the old
// session to answer its keepalive. A var so tests can shorten it.
var returnProbeWait = 5 * time.Second

// oldSessionAnswers sends one keepalive on the old session and reports
// whether the server answered it - or anything came down - within
// returnProbeWait. A return whose handshake went out unanswered may have
// displaced the old session on the same exit; it may as well not have, and
// tearing the tunnel down then lost a healthy one to a swallowed family
// (P2-3 of the round-10 review: three reconnects into the silent family).
func (v *VPNClient) oldSessionAnswers(oldConn net.Conn) bool {
	v.mu.Lock()
	lastRx := v.lastRx
	v.mu.Unlock()
	echoes := v.keepaliveEchoes.Load()
	// Written here rather than through writeSilenceKeepalive, which skips a
	// keepalive right after another: this one is a question.
	v.keepaliveMu.Lock()
	_ = oldConn.SetWriteDeadline(time.Now().Add(keepaliveWriteTimeout))
	_, err := oldConn.Write([]byte{0, 0, 0, 0})
	if err == nil {
		now := monoNow()
		v.lastTx.Store(now)
		v.lastKeepalive.Store(now)
	}
	v.keepaliveMu.Unlock()
	if err != nil {
		return false
	}
	deadline := time.Now().Add(returnProbeWait)
	for time.Now().Before(deadline) {
		v.mu.Lock()
		heard := v.lastRx.After(lastRx)
		cur := v.conn
		v.mu.Unlock()
		if cur != oldConn {
			return false
		}
		if heard || v.keepaliveEchoes.Load() > echoes {
			return true
		}
		select {
		case <-v.stopCh:
			return false
		case <-time.After(20 * time.Millisecond):
		}
	}
	return false
}
