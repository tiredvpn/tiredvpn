package server

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
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
			// The certificate's signature field carries the MAC that proves this
			// server to the client (cert-HMAC, task 011). The minted certificate
			// stays cached per SNI; only the signature is per connection, and the
			// key for it rides on the connection from the gate.
			return customtls.CertificateForHello(chi, name, minter.certForSNI)
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
func handleREALITYB1(conn net.Conn, peekBuf []byte, clientID clientIdentity, secret []byte, clientFlags byte, srvCtx *serverContext, logger *log.Logger) {
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

	// Derive the connection's auth key and carry it on the connection so
	// GetCertificate can reach it. It cannot derive the key itself: the callback
	// receives a *tls.ClientHelloInfo, which has the parsed SNI but neither the
	// raw ClientHello nor the client's key share.
	//
	// This repeats the X25519 the gate already did. One curve operation against
	// a full TLS handshake is not worth threading the value out of the gate and
	// widening its signature for.
	authKey, err := b1AuthKey(peekBuf)
	if err != nil {
		// The gate accepted this ClientHello moments ago, so failing here means
		// the buffer changed under us. Close without a reply, like every other
		// rejection on this path.
		logger.Debug("REALITY B1: auth key derivation failed for %s: %v", clientID, err)
		_ = conn.Close()
		return
	}

	// Nesting order is load-bearing in both directions. The record guard sits
	// innermost, against the socket, or it would be counting bytes crypto/tls
	// had already consumed. The auth conn sits outermost, because it is what
	// GetCertificate reaches through ClientHelloInfo.Conn.
	tlsConn := tls.Server(customtls.NewAuthConn(guard, authKey), cfg)
	err = tlsConn.Handshake()
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

	// One-way clock hint. The client does not wait for it: proving this server
	// to the client is cert-HMAC's job and it already happened inside the
	// handshake, so making this synchronous would cost a round trip on every
	// CONNECT for a value that only matters to the client's next connection.
	if err := customtls.WriteServerTime(tlsConn, time.Now()); err != nil {
		logger.Debug("REALITY B1: server time write failed: %v", err)
		return
	}

	realityAuthB1Total.Add(1)

	// Whether this client can tolerate server-initiated reshaping. Reshaping is
	// the server's decision and this is the only input to it: a client that did
	// not advertise the bit is left alone, which is what makes it safe to run
	// old and new clients against the same server during a rollout.
	//
	// Nothing reads this yet - the reshaping itself lands in its own change.
	// The negotiation ships first on purpose, so that by the time reshaping
	// exists there are already clients in the field advertising support for it.
	reshapeOK := clientFlags&customtls.AuthFlagReshapeCapable != 0
	if reshapeOK {
		realityReshapeCapableTotal.Add(1)
	}
	logger.Info("REALITY B1: tunnel established for %s (client: %s, reshape-capable: %v)",
		conn.RemoteAddr(), clientID, reshapeOK)

	if dispatch != protocol.TypeMux {
		// Single-stream mode: the tunnel runs directly over TLS.
		handleRawTunnel(tlsConn, srvCtx, logger, clientID)
		return
	}

	// No keepalive on either side of a B1 session. smux's default NOP every ten
	// seconds is a perfectly periodic pulse that identifies the session from
	// timestamps alone - see mux.SmuxSilentConfig.
	//
	// This needs no version negotiation, which is why it lands here and not on
	// the legacy path. B1 has never shipped, so every peer that ever speaks it
	// has this build's behaviour by construction; the legacy transport has
	// deployed clients that would kill an idle session after thirty seconds of
	// the silence, and it keeps its keepalive until it is retired.
	sess, err := smux.Server(tlsConn, mux.SmuxSilentConfig())
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

// b1AuthKey derives the connection's authentication key from the peeked
// ClientHello: X25519 between the server's static key and the client's key
// share, then HKDF salted with the ClientHello random. It is the same value the
// gate derived to open session_id, and the same one the client holds.
func b1AuthKey(peekBuf []byte) ([]byte, error) {
	if len(peekBuf) <= tlsRecordHeaderLen {
		return nil, customtls.ErrHelloTruncated
	}
	helloRaw := peekBuf[tlsRecordHeaderLen:]

	peerPub, err := customtls.ExtractPeerX25519(helloRaw)
	if err != nil {
		return nil, err
	}
	random, err := helloRandom(helloRaw)
	if err != nil {
		return nil, err
	}
	serverPriv, _ := realityStaticKeys()
	return customtls.ServerAuthKey(serverPriv[:], peerPub, random)
}
