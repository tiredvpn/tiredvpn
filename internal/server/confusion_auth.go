package server

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// Authentication for the confusion transport, and the only place it happens.
//
// In 1.10.0 there was none. handleProtocolConfusion scanned the first bytes for
// the literal "TIRED", answered "TIRED", read an address out of the same packet
// and dialled it; handleConfusionTUNMode derived the client's identity from its
// source address and handed it an address out of the pool. Five bytes from any
// host on the internet bought a TCP relay through the exit, and the answer
// identified the server in one round trip.
//
// Now every confusion connection passes through classifyConfusion first. It
// parses the carrier, recomputes the marker for each secret the server knows,
// and only on a match does anything else happen - no dial, no allocation, no
// byte written back. A peer that fails gets exactly what every other unknown
// peer gets, because the caller falls through to the same detectors and the
// same fake website.

// confusionAuthTimeout bounds how long a peer may take over its opening
// carrier. A peer that dribbles bytes holds one goroutine and nothing else.
const confusionAuthTimeout = 10 * time.Second

// confusionSession is an authenticated confusion connection.
type confusionSession struct {
	// raw is the socket, for deadlines and peer address.
	raw net.Conn

	// conn is the sealed record layer. Everything after the opening carrier
	// goes through it, so there is no path where payload reaches the socket in
	// the clear.
	conn *strategy.ConfusionServerConn

	// clientID is derived from the secret that matched, never from the peer's
	// address. Behind a relay every client shares one address, which is why
	// the old derivation handed them all one lease.
	clientID clientIdentity

	secret []byte
}

// confusionReplayWindow and confusionReplayMax bound the nonce cache. A captured
// opening packet proves nothing to whoever replays it - they cannot derive the
// record keys - but it would still make the server dial the original target
// once per replay, so the nonce is spent on first use.
const (
	confusionReplayWindow = 10 * time.Minute
	confusionReplayMax    = 8192
)

type confusionReplayGuard struct {
	mu   sync.Mutex
	seen map[[strategy.ConfusionNonceLen]byte]time.Time
}

var confusionReplays = &confusionReplayGuard{
	seen: make(map[[strategy.ConfusionNonceLen]byte]time.Time),
}

// admit records nonce and reports whether it is new.
func (g *confusionReplayGuard) admit(nonce []byte, now time.Time) bool {
	if len(nonce) != strategy.ConfusionNonceLen {
		return false
	}
	var key [strategy.ConfusionNonceLen]byte
	copy(key[:], nonce)

	g.mu.Lock()
	defer g.mu.Unlock()

	if seenAt, ok := g.seen[key]; ok && now.Sub(seenAt) < confusionReplayWindow {
		return false
	}
	if len(g.seen) >= confusionReplayMax {
		for k, t := range g.seen {
			if now.Sub(t) >= confusionReplayWindow {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= confusionReplayMax {
			// Still full of live entries: drop the cache rather than grow
			// without bound. The window reopens for whatever was in it, which
			// is a far smaller price than unbounded memory.
			g.seen = make(map[[strategy.ConfusionNonceLen]byte]time.Time, confusionReplayMax)
		}
	}
	g.seen[key] = now
	return true
}

// detectConfusionMagic is the cheap pre-filter: does this peek look like one of
// the five carriers at all?
//
// It used to return true for any buffer containing the ASCII "TIRED" and - the
// worse half - for any buffer whose fifth and sixth bytes read 0x01 0x00, which
// made the relay reachable with no marker of ours anywhere in the packet. Both
// rules are gone. What is left is a real parse of the carrier: either it is a
// well-formed instance of one of the five shapes, or it is not ours.
//
// It is only a pre-filter. It says nothing about who is calling; that is
// classifyConfusion's job, and nothing happens on the strength of this function
// alone.
func detectConfusionMagic(data []byte) bool {
	_, err := strategy.ParseConfusionRequest(data)
	return err == nil || errors.Is(err, strategy.ErrConfusionNeedMore)
}

// classifyConfusion reads the opening carrier and authenticates it.
//
// On success it returns a session whose record layer is ready. On failure it
// returns every byte it consumed, so the caller can replay them in front of the
// next detector - an unauthenticated peer must not even be able to tell that
// the bytes were looked at by this path.
func classifyConfusion(conn net.Conn, peek []byte, srvCtx *serverContext, logger *log.Logger) (*confusionSession, []byte, bool) {
	// Cheap reject first, so ordinary traffic costs one parse and no reads.
	if !detectConfusionMagic(peek) {
		return nil, nil, false
	}

	conn.SetReadDeadline(time.Now().Add(confusionAuthTimeout))
	req, leftover, consumed, err := strategy.ReadConfusionRequest(conn, nil)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		logger.Debug("Confusion: carrier did not parse: %v", err)
		return nil, consumed, false
	}

	secret, clientID, ok := matchConfusionSecret(req, srvCtx)
	if !ok {
		logger.Debug("Confusion: no secret matches the marker, treating as unknown peer")
		return nil, consumed, false
	}

	if !confusionReplays.admit(req.Nonce, time.Now()) {
		logger.Warn("Confusion: replayed opening nonce from %s, refusing", conn.RemoteAddr())
		return nil, consumed, false
	}

	markerLen, _ := strategy.MatchConfusionClientMarker(secret, req.Nonce, req.Variant, req.Body)
	sealed, err := strategy.NewConfusionServerConn(conn, req, secret, req.Body[markerLen:], leftover)
	if err != nil {
		logger.Debug("Confusion: record layer setup failed: %v", err)
		return nil, consumed, false
	}

	logger.Debug("Confusion authenticated (variant=%d, client=%s)", req.Variant, clientID)
	return &confusionSession{raw: conn, conn: sealed, clientID: clientID, secret: secret}, consumed, true
}

// matchConfusionSecret recomputes the marker for every secret the server knows
// and returns the one that matches, together with the identity it names.
//
// Registry clients are tried first and each has its own secret, so a match
// there is a per-client identity that keys a lease on its own. The global
// secret is the fallback and is shared, so its identity is marked as such - two
// clients presenting it are not distinguishable and must not be handed one
// lease between them.
func matchConfusionSecret(req *strategy.ConfusionCarrier, srvCtx *serverContext) ([]byte, clientIdentity, bool) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			secret := []byte(client.Secret)
			if _, ok := strategy.MatchConfusionClientMarker(secret, req.Nonce, req.Variant, req.Body); ok {
				return secret, registryIdentity(client.ID), true
			}
		}
	}

	if len(srvCtx.cfg.Secret) > 0 {
		if _, ok := strategy.MatchConfusionClientMarker(srvCtx.cfg.Secret, req.Nonce, req.Variant, req.Body); ok {
			return srvCtx.cfg.Secret, sharedIdentity(globalClientID), true
		}
	}

	return nil, clientIdentity{}, false
}
