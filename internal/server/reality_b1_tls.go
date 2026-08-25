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
func handleREALITYB1(conn net.Conn, peekBuf []byte, clientID string, secret []byte, clientFlags byte, srvCtx *serverContext, logger *log.Logger) {
	cfg, _ := b1TLSFor(srvCtx)

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

	tlsConn := tls.Server(customtls.NewAuthConn(conn, authKey), cfg)
	if err := tlsConn.Handshake(); err != nil {
		// No alert, no reset with a distinguishing shape: just close. A failed
		// handshake here is either a broken client or someone who stole a
		// session_id, and neither deserves a reply that confirms anything.
		logger.Debug("REALITY B1: TLS handshake failed for %s: %v", clientID, err)
		_ = tlsConn.Close()
		return
	}
	defer tlsConn.Close()

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
