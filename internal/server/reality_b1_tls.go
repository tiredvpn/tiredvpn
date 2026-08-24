package server

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// The B1 server answers with the same key exchange the shared listener does,
// from the same donor table (curvePreferencesFor). Classic by default, hybrid
// under the two donors that genuinely negotiate ML-KEM.
//
// Both branches on classic is one decision, not two. Eleven of thirteen donors
// send a 133-byte plaintext ServerHello where the hybrid makes ours 1221, and
// B1 presents itself under a donor's SNI, so the 1088 extra bytes would ride in
// the ServerHello of every real B1 connection. Two paths answering differently
// on one port would be a signal in itself, and a worse one than what we started
// with - so if the group ever moves, it moves in both.
//
// Worth recording for whoever revisits this: the cost is lower here than on the
// shared listener. For stego, morph, websocket-padded, http-polling and
// anti-probe the outer TLS is the only confidentiality they have, so dropping
// the hybrid is a real trade. Under B1 it is not the only layer - the client's
// X25519 in session_id and the AEAD channel underneath both stand on their own.

// b1TLSConfig builds the TLS 1.3 configuration for the B1 transport.
//
// Separate from srvCtx.tlsConfig on purpose: that one allows TLS 1.2 and serves
// one fixed certificate, both of which would be wrong here.
func b1TLSConfig(minter *certMinter, coverDomain string) *tls.Config {
	base := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: classicCurves,
		NextProtos:       []string{"h2", "http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				// A client with no SNI still needs a name on the certificate.
				// The cover domain is the operator's answer to "what site is
				// this"; without one, any fixed name beats failing the
				// handshake, which would be a distinguishing behaviour of its own.
				name = coverDomain
				if name == "" {
					name = defaultCertName
				}
			}
			return minter.certForSNI(name)
		},
		// Session tickets stay on: a real server issues them, and a server that
		// never does is a server that stands out.
	}

	hybrid := base.Clone()
	hybrid.CurvePreferences = hybridCurves

	base.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if keyExchangeFor(chi.ServerName) == kxHybrid {
			return hybrid, nil
		}
		return nil, nil
	}
	return base
}

// defaultCertName is used when a client sends no SNI and no cover domain is
// configured.
const defaultCertName = "www.microsoft.com"

// b1HandshakeTimeout bounds the TLS handshake for an authenticated client. A
// real handshake takes milliseconds; this is wide enough for a bad link and
// narrow enough that holding one open costs an attacker a connection per ten
// seconds rather than being free.
const b1HandshakeTimeout = 10 * time.Second

// b1HandshakeSafetyPolicy caps ChangeCipherSpec records during that handshake.
//
// Deliberately not a donor number. Donor tolerances exist to make a prober see
// the site we claim to be, and a client that got this far is past the point
// where that matters. Eight is far more than the one a real client sends and
// far less than the thirty-odd a donor would swallow.
var b1HandshakeSafetyPolicy = ccsPolicy{Mechanism: ccsCount, Limit: 8}

// b1TLS holds the per-server TLS state for the B1 transport.
type b1TLS struct {
	once   sync.Once
	minter *certMinter
	cfg    *tls.Config
}

var b1TLSState b1TLS

// b1TLSFor returns the process-wide TLS configuration, built on first use.
func b1TLSFor(srvCtx *serverContext) (*tls.Config, *certMinter) {
	b1TLSState.once.Do(func() {
		b1TLSState.minter = newCertMinter()
		b1TLSState.cfg = b1TLSConfig(b1TLSState.minter, srvCtx.cfg.REALITYCoverDomain)
	})
	return b1TLSState.cfg, b1TLSState.minter
}

// handleREALITYB1 terminates TLS for an authenticated client and runs the
// tunnel over it.
//
// conn is the buffered connection that still replays the ClientHello, so
// crypto/tls reads the same bytes the gate already inspected - the same
// mechanism the plain TLS path uses.
func handleREALITYB1(conn net.Conn, peekBuf []byte, clientID string, secret []byte, srvCtx *serverContext, logger *log.Logger) {
	_ = peekBuf // replayed through conn; kept in the signature for stream B

	cfg, _ := b1TLSFor(srvCtx)

	// Bound the handshake explicitly. Until now the only thing stopping a
	// client from holding one open was a 30-second read deadline inherited
	// from the peek loop, which is neither a chosen number nor a guarantee:
	// crypto/tls resets its own useless-record counter on any record that
	// advances the handshake, so a client holding the handshake keys can
	// alternate ChangeCipherSpec with encrypted fragments and never trip it.
	//
	// This is a safety bound, not imitation. A client that reaches here has
	// authenticated; there is nobody left to convince that we are yandex, and
	// the donor tolerances have no business governing what our own users may
	// do to us.
	_ = conn.SetDeadline(time.Now().Add(b1HandshakeTimeout))
	guard := newCCSGuardWithPolicy(conn, b1HandshakeSafetyPolicy)

	tlsConn := tls.Server(guard, cfg)
	err := tlsConn.Handshake()
	guard.handshakeDone()
	if err != nil {
		// No alert, no reset with a distinguishing shape: just close. A failed
		// handshake here is either a broken client or someone who stole a
		// session_id, and neither deserves a reply that confirms anything.
		logger.Debug("REALITY B1: TLS handshake failed for %s: %v", clientID, err)
		_ = tlsConn.Close()
		return
	}
	defer tlsConn.Close()

	// The tunnel is not a handshake and must not inherit its deadline. Without
	// this the connection stops reading at whatever absolute time the peek loop
	// picked, which would have killed every B1 tunnel 30 seconds in.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Debug("REALITY B1: clearing the handshake deadline failed: %v", err)
	}

	state := tlsConn.ConnectionState()
	logger.Debug("REALITY B1: TLS up (client: %s, alpn: %q, sni: %q)", clientID, state.NegotiatedProtocol, state.ServerName)

	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		logger.Debug("REALITY B1: exporter failed: %v", err)
		return
	}

	dispatch, err := customtls.ReadClientBinding(tlsConn, secret, ekm)
	switch {
	case errors.Is(err, customtls.ErrBindingMismatch):
		// Authenticated in session_id but cannot prove it holds the secret over
		// this handshake: a replay, or someone who lifted a session_id off the
		// wire. It gets the fake website over the TLS session that is already
		// up, rather than a reset - the connection continues to look like a
		// visit to a website, which is what it claimed to be.
		logger.Info("REALITY B1: binding mismatch for %s, serving the fake website", clientID)
		serveFakeWebsite(tlsConn, srvCtx.cfg, logger)
		return
	case err != nil:
		logger.Debug("REALITY B1: binding read failed: %v", err)
		return
	}

	if err := customtls.WriteServerBinding(tlsConn, secret, ekm, time.Now()); err != nil {
		logger.Debug("REALITY B1: binding write failed: %v", err)
		return
	}

	realityAuthB1Total.Add(1)
	logger.Info("REALITY B1: tunnel established for %s (client: %s)", conn.RemoteAddr(), clientID)

	if dispatch != protocol.TypeMux {
		// Single-stream mode: the tunnel runs directly over TLS.
		handleRawTunnel(tlsConn, srvCtx, logger, clientID)
		return
	}

	sess, err := smux.Server(tlsConn, smux.DefaultConfig())
	if err != nil {
		logger.Error("REALITY B1: smux server: %v", err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			logger.Debug("REALITY B1: smux session closed: %v", err)
			return
		}
		go handleRawTunnel(stream, srvCtx, logger, clientID)
	}
}
