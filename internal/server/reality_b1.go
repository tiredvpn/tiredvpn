package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
	"github.com/tiredvpn/tiredvpn/internal/log"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// Authentication counters. They answer one question the epic asks directly: is
// anyone still on the legacy transport? Once the legacy counter stops moving,
// -reality-legacy can be switched off.
var (
	realityAuthB1Total     atomic.Uint64
	realityAuthLegacyTotal atomic.Uint64

	// realityDonorDialFailTotal counts unauthenticated connections we could not
	// hand to a donor because the dial failed.
	//
	// It exists because that failure is otherwise invisible. Where an operator
	// relies on -reality-cover-domain to cover the padding-extension behaviour
	// on a server that has not been updated, a donor that stops being reachable
	// silently takes the cover with it: the connection ends up closed, which is
	// the shape the cover was meant to avoid, and nothing in the log says so.
	realityDonorDialFailTotal atomic.Uint64

	// realityReshapeCapableTotal counts authenticated B1 clients that advertised
	// they can tolerate server-initiated reshaping. It is the number that says
	// when the field has caught up enough for the server side to be switched on.
	realityReshapeCapableTotal atomic.Uint64
)

// realityB1Gate holds the state the gate needs across connections.
type realityB1Gate struct {
	index  *shortIDIndex
	replay *replayCache
}

func newREALITYB1Gate(maxTimeDiff int) *realityB1Gate {
	return &realityB1Gate{
		index:  newShortIDIndex(),
		replay: newReplayCache(replayTTLFor(maxTimeDiff)),
	}
}

var (
	b1GateOnce sync.Once
	b1Gate     *realityB1Gate
)

// gateFor returns the process-wide gate, built on first use. One server runs
// per process, and the gate is keyed to that server's static key, so a
// singleton is the honest shape; tests construct their own instead.
func gateFor(srvCtx *serverContext) *realityB1Gate {
	b1GateOnce.Do(func() {
		b1Gate = newREALITYB1Gate(srvCtx.cfg.REALITYMaxTimeDiff)
		var clients []*ClientConfig
		if srvCtx.registry != nil {
			clients = srvCtx.registry.ListClients()
		}
		b1Gate.index.Rebuild(clients, srvCtx.cfg.Secret)
	})
	return b1Gate
}

// tryREALITYB1 reports whether the connection was served by the B1 transport.
//
// This is the dispatcher's single entry point into B1. Everything B1 needs
// arrives through srvCtx, so filling it in never means editing a shared file.
//
// Return values carry a distinction worth stating plainly:
//
//   - false means "this is not a TLS ClientHello I can even parse". The
//     dispatcher goes on to try the legacy detector and then plain TLS, so
//     other protocols are not swallowed.
//   - true means the connection is spoken for, either because a client
//     authenticated or because it did not and got the donor site instead.
//     Everything that is a ClientHello ends here, which is the point: a prober
//     must not be able to tell our server from the site it is impersonating.
//
// B1.5 hooks in here. Its adaptive mirroring wants to open the donor
// connection before the verdict for sources it has not seen, and this is the
// only place with both the client address and the ClientHello in hand - the
// dispatcher has neither the address logic nor any business knowing about
// donors. srvCtx.cfg.REALITYMirrorMode is already parsed and validated.
func tryREALITYB1(conn net.Conn, peekBuf []byte, srvCtx *serverContext, logger *log.Logger) bool {
	if len(peekBuf) <= tlsRecordHeaderLen {
		return false
	}
	helloRaw := peekBuf[tlsRecordHeaderLen:]

	now := time.Now()

	// Open the donor connection alongside the gate rather than after it, for
	// sources we have no reason to trust yet. A prober always arrives from such
	// a source; a user's address is vouched for by its last successful
	// handshake and costs no donor traffic at all. See reality_mirror.go.
	var donor <-chan donorHandoff
	if shouldMirror(srvCtx.cfg.REALITYMirrorMode, conn.RemoteAddr(), now) {
		donor = dialDonorEagerly(peekBuf, srvCtx)
	}

	gate := gateFor(srvCtx)
	verdict, err := gate.evaluate(srvCtx, helloRaw, now)
	if err != nil {
		releaseDonor(donor)
		// Structurally not a ClientHello we can read. Hand it back rather than
		// consume it: this is the only path that must not claim the connection.
		return false
	}

	if !verdict.ok {
		gate.refreshIndexIfNeeded(srvCtx, verdict)

		// A client on the old transport reaches this point too, and its
		// ClientHello parses perfectly well - it just was not sealed to our
		// static key, because the legacy scheme does not use one. Sending it to
		// the donor would break every existing client the moment an operator
		// turns B1 on, so hand it back for the legacy detector that runs next.
		//
		// This does make "carries a padding extension" observable, since such a
		// connection ends up at the cover domain rather than at the requested
		// donor. That difference is already there today - the legacy path is the
		// only path - and it goes away with -reality-legacy=false, which is the
		// end state of the rollout.
		if srvCtx.cfg.REALITYLegacyEnabled && DetectREALITYExtension(peekBuf) {
			logger.Debug("REALITY B1: no match (%s), deferring to the legacy transport", verdict.reason)
			releaseDonor(donor)
			return false
		}

		// Every other rejection lands here, and they must be indistinguishable.
		// The reason is logged locally and never signalled to the peer: same
		// destination, same bytes, same delay.
		logger.Debug("REALITY B1: no match (%s), serving donor", verdict.reason)
		return realityDonorFallback(conn, peekBuf, donor, srvCtx, logger)
	}

	// Authenticated: this source needs no donor now and none next time either.
	releaseDonor(donor)
	reputation.remember(conn.RemoteAddr(), now)

	// The counter moves in handleREALITYB1, after the binding proves the client
	// holds the secret. Counting here would count anyone who got a short ID
	// right, which is not the same thing.
	logger.Debug("REALITY B1: session_id accepted (client: %s, flags %#02x)", verdict.entry.clientID, verdict.flags)
	handleREALITYB1(conn, peekBuf, verdict.entry.clientID, verdict.entry.secret, verdict.flags, srvCtx, logger)
	return true
}

// tlsRecordHeaderLen is the TLS record header the peek buffer starts with.
const tlsRecordHeaderLen = 5

// b1Reason names why a ClientHello did not authenticate. It exists for the log
// only: nothing about it may reach the wire, or the version field turns into an
// oracle a censor can query.
type b1Reason string

const (
	reasonAuthenticated b1Reason = "authenticated"
	reasonNotSealed     b1Reason = "session_id did not open"
	reasonClockSkew     b1Reason = "timestamp outside tolerated skew"
	reasonOldClient     b1Reason = "client older than the configured minimum"
	reasonUnknownID     b1Reason = "short id not in the index"
	reasonReplay        b1Reason = "session_id seen before"
)

// b1Verdict is the outcome of the gate for one ClientHello.
type b1Verdict struct {
	ok     bool
	reason b1Reason
	entry  shortIDEntry

	// flags are the client's advertised capabilities, read out of the sealed
	// session_id. Meaningful only when ok is true: on any other verdict the
	// payload either did not open or did not authenticate, so its contents
	// prove nothing.
	flags byte
}

// evaluate runs the gate: one X25519, one AEAD open, one map lookup.
//
// A non-nil error means the input is not a ClientHello we can parse, which is
// the only case the caller passes back to the dispatcher. Everything else comes
// back as a verdict, because from the outside those all have to look the same.
//
// The policy checks below are written without early returns on purpose. Bailing
// out at the first failure would make a bad timestamp cheaper to reject than an
// unknown short ID, and the difference is measurable from outside. So the
// expensive part - the key agreement and the AEAD - runs before any policy is
// consulted, and every policy runs regardless of what the previous one said.
func (g *realityB1Gate) evaluate(srvCtx *serverContext, helloRaw []byte, now time.Time) (b1Verdict, error) {
	sessionID, err := customtls.SessionIDFrom(helloRaw)
	if err != nil {
		return b1Verdict{}, err
	}
	peerPub, err := customtls.ExtractPeerX25519(helloRaw)
	if err != nil {
		return b1Verdict{}, err
	}
	zeroed, err := customtls.ZeroSessionID(helloRaw)
	if err != nil {
		return b1Verdict{}, err
	}
	random, err := helloRandom(helloRaw)
	if err != nil {
		return b1Verdict{}, err
	}

	serverPriv, _ := realityStaticKeys()
	payload, err := customtls.OpenSessionID(serverPriv[:], peerPub, zeroed, random, sessionID)
	if err != nil {
		// Anyone can seal something that opens here - the server's public key
		// is public, so this proves nothing about the sender. It only means
		// "shaped like ours". The short ID below is the actual authentication.
		return b1Verdict{reason: reasonNotSealed}, nil
	}

	cfg := srvCtx.cfg
	timeOK := withinSkew(payload.Time, now, cfg.REALITYMaxTimeDiff)
	versionOK := versionAtLeast(payload.Version, cfg.REALITYMinClientVer)
	entry, idOK := g.index.Lookup(payload.ShortID)

	// Recorded only for a known short ID. A forged payload opens fine, so
	// recording every one that did would let anyone fill the cache; the cost is
	// a map insert that a rejected connection skips, which is nanoseconds
	// against a donor dial.
	freshOK := true
	if idOK {
		freshOK = g.replay.checkAndRecord(sessionID, now)
	}

	switch {
	case !timeOK:
		return b1Verdict{reason: reasonClockSkew}, nil
	case !versionOK:
		return b1Verdict{reason: reasonOldClient}, nil
	case !idOK:
		return b1Verdict{reason: reasonUnknownID}, nil
	case !freshOK:
		return b1Verdict{reason: reasonReplay}, nil
	}

	return b1Verdict{ok: true, reason: reasonAuthenticated, entry: entry, flags: payload.Flags}, nil
}

// refreshIndexIfNeeded rebuilds the short-ID index in the background when it is
// stale, or when a lookup missed and the index has not been rebuilt recently.
// A miss is the only signal available that a client was added, and the rate
// limit is what stops that signal from being a DoS lever.
func (g *realityB1Gate) refreshIndexIfNeeded(srvCtx *serverContext, verdict b1Verdict) {
	switch {
	case verdict.reason == reasonUnknownID:
		g.index.refreshAsync(srvCtx, shortIDMissRefreshInterval)
	case g.index.stale(time.Now()):
		g.index.refreshAsync(srvCtx, shortIDRefreshInterval)
	}
}

// helloRandom returns the 32-byte ClientHello.Random.
//
// The offset is fixed by RFC 8446: msg_type(1) + length(3) + legacy_version(2).
// Unlike session_id, whose length varies by profile and must be parsed, none of
// these three fields can be any other size in a ClientHello.
func helloRandom(helloRaw []byte) ([]byte, error) {
	const randomOffset = 4 + 2
	if len(helloRaw) < randomOffset+32 {
		return nil, customtls.ErrHelloTruncated
	}
	return helloRaw[randomOffset : randomOffset+32], nil
}

// withinSkew reports whether a client timestamp is close enough to ours.
// maxDiff <= 0 disables the check.
func withinSkew(clientUnix uint32, now time.Time, maxDiff int) bool {
	if maxDiff <= 0 {
		return true
	}
	diff := now.Unix() - int64(clientUnix)
	if diff < 0 {
		diff = -diff
	}
	return diff <= int64(maxDiff)
}

// versionAtLeast compares a client version against the configured minimum.
// An empty minimum disables the check; a malformed one is rejected at startup
// (validateREALITYConfig), so it cannot silently lock every client out here.
func versionAtLeast(version [3]byte, minVer string) bool {
	if minVer == "" {
		return true
	}
	want, err := parseClientVersion(minVer)
	if err != nil {
		return true
	}
	for i := range version {
		if version[i] != want[i] {
			return version[i] > want[i]
		}
	}
	return true
}

// realityDonorFallback is what a connection gets when it did not authenticate:
// a transparent proxy to a real site, so a prober sees that site and not us.
//
// Destination policy, unchanged from the legacy path and deliberately narrow:
// the requested SNI if it is on our fixed allowlist, otherwise the operator's
// cover domain, otherwise nothing. The allowlist is compiled in and never
// derived from client input, so there is no SSRF here by construction - while a
// prober asking for a name on the list still gets that name's certificate.
//
// peekBuf goes to the donor byte for byte. B1 carries no padding extension, so
// unlike the legacy path there is nothing to strip.
// realityDonorFallback proxies an unauthenticated ClientHello to a donor.
//
// It reports whether it served the connection. False means there was no donor
// to send it to and the caller must fall through to the ordinary TLS path.
// Closing instead would answer a ClientHello with a bare FIN, and that silence
// is what let one packet tell our servers apart from every other host: no
// ServerHello, no alert, just a close. The ordinary path terminates TLS and
// serves the decoy, which is what any unrecognised connection gets.
func realityDonorFallback(conn net.Conn, peekBuf []byte, donor <-chan donorHandoff, srvCtx *serverContext, logger *log.Logger) bool {
	destConn, dest, err := awaitDonor(donor, peekBuf, srvCtx)
	if err != nil {
		if !errors.Is(err, errNoDonor) {
			logger.Debug("REALITY B1: donor %s unreachable: %v", dest, err)
			realityDonorDialFailTotal.Add(1)
		}
		// Hand it back rather than close. A donor that is merely unreachable
		// must not turn into the silence we removed - and an unreachable donor
		// is otherwise invisible, which is what the counter above is for.
		logger.Debug("REALITY B1: no donor for this ClientHello, handing back to the ordinary path")
		return false
	}
	defer destConn.Close()

	if _, err := destConn.Write(peekBuf); err != nil {
		logger.Debug("REALITY B1: forwarding to donor %s failed: %v", dest, err)
		return true // the donor was reached; the connection is spent either way
	}

	logger.Debug("REALITY B1: proxying %s to donor %s", conn.RemoteAddr(), dest)
	proxyBothWays(conn, destConn)
	return true
}

// awaitDonor takes the eagerly dialled connection if there is one, and dials on
// the spot if there is not. The lazy dial is what an address we already trust
// gets when its handshake turns out to be broken after all.
func awaitDonor(donor <-chan donorHandoff, peekBuf []byte, srvCtx *serverContext) (net.Conn, string, error) {
	if donor != nil {
		h := <-donor
		return h.conn, h.dest, h.err
	}

	dest := donorDestination(peekBuf, srvCtx.cfg.REALITYCoverDomain)
	if dest == "" {
		return nil, "", errNoDonor
	}
	realityDonorDialsLazy.Add(1)
	c, err := net.DialTimeout("tcp", net.JoinHostPort(dest, "443"), 10*time.Second)
	return c, dest, err
}

// releaseDonor closes an eagerly dialled connection nobody needs. Waiting for
// the dial in a goroutine keeps the caller off the donor's round trip.
func releaseDonor(donor <-chan donorHandoff) {
	if donor == nil {
		return
	}
	go func() {
		if h := <-donor; h.conn != nil {
			_ = h.conn.Close()
		}
	}()
}

// donorDestination applies the destination policy to a ClientHello.
func donorDestination(peekBuf []byte, coverDomain string) string {
	sni, err := ExtractSNI(peekBuf)
	if err == nil && sniAllowlisted(sni) {
		return sni
	}
	return coverDomain
}

// sniAllowlisted reports whether a hostname is one of the donors we are willing
// to open a connection to.
func sniAllowlisted(sni string) bool {
	for _, entry := range evasion.WhitelistedSNIs {
		if entry.SNI == sni {
			return true
		}
	}
	return false
}

// proxyBothWays copies in both directions until either side finishes, passing
// the half-close along rather than tearing the whole thing down on the first
// FIN. A donor that sees an abrupt reset where a browser would have sent FIN
// behaves differently in reply, and that difference is visible to whoever is
// watching us.
func proxyBothWays(client, donor net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(donor, client)
		closeWrite(donor)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, donor)
		closeWrite(client)
	}()

	wg.Wait()
}

// closeWrite half-closes a connection if the underlying type supports it.
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// handleREALITYB1 lives in reality_b1_tls.go: it terminates TLS 1.3, checks the
// exporter binding and runs the tunnel over it.

// writeREALITYAuthMetrics renders the per-transport authentication counters.
// They exist to answer one operational question - is anyone still on the legacy
// transport - so the legacy counter going flat is the signal that
// -reality-legacy can be turned off.
func writeREALITYAuthMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP reality_auth_b1_total REALITY clients authenticated via the B1 transport\n")
	fmt.Fprintf(w, "# TYPE reality_auth_b1_total counter\n")
	fmt.Fprintf(w, "reality_auth_b1_total %d\n", realityAuthB1Total.Load())
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP reality_reshape_capable_total Authenticated B1 clients that advertised tolerance for server-initiated reshaping\n")
	fmt.Fprintf(w, "# TYPE reality_reshape_capable_total counter\n")
	fmt.Fprintf(w, "reality_reshape_capable_total %d\n", realityReshapeCapableTotal.Load())
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP reality_donor_dial_fail_total Unauthenticated connections that could not be handed to a donor because the dial failed\n")
	fmt.Fprintf(w, "# TYPE reality_donor_dial_fail_total counter\n")
	fmt.Fprintf(w, "reality_donor_dial_fail_total %d\n", realityDonorDialFailTotal.Load())
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP reality_auth_legacy_total REALITY clients authenticated via the legacy padding-extension transport\n")
	fmt.Fprintf(w, "# TYPE reality_auth_legacy_total counter\n")
	fmt.Fprintf(w, "reality_auth_legacy_total %d\n", realityAuthLegacyTotal.Load())
	fmt.Fprintf(w, "\n")
}
