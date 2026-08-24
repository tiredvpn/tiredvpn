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

// b1CurvePreferences is the key-exchange group list for the B1 server.
//
// Hybrid first, because a client on a current browser profile offers both
// X25519MLKEM768 and X25519, and a modern site picks the hybrid. Choosing plain
// X25519 when the hybrid was offered would differ from what the client would
// have seen at the donor.
//
// Note for whoever owns the group choice next: the donor measurements
// (research/donor-profiles-2026-08-25.md) found eleven of thirteen donors
// answering with classic X25519 and a 133-byte plaintext ServerHello, against
// 1221 bytes when the hybrid is selected. Those measurements were taken against
// the plain TLS branch rather than this one, so they are that branch's problem
// to fix - but the same 1088 bytes ride in the ServerHello of every real B1
// connection, under a donor SNI. Whatever is decided for initTLSConfig has to
// be decided here too, or the two paths answer differently on one port.
var b1CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}

// b1TLSConfig builds the TLS 1.3 configuration for the B1 transport.
//
// Separate from srvCtx.tlsConfig on purpose: that one allows TLS 1.2 and serves
// one fixed certificate, both of which would be wrong here.
func b1TLSConfig(minter *certMinter, coverDomain string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: b1CurvePreferences,
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
func handleREALITYB1(conn net.Conn, peekBuf []byte, clientID string, secret []byte, srvCtx *serverContext, logger *log.Logger) {
	_ = peekBuf // replayed through conn; kept in the signature for stream B

	cfg, _ := b1TLSFor(srvCtx)

	tlsConn := tls.Server(conn, cfg)
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
