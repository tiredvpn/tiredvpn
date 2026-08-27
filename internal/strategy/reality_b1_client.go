package strategy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// The B1 client: a real TLS 1.3 handshake, authentication hidden in session_id.
//
// What this replaces is worth stating, because the difference is the point.
// The legacy path takes ClientHello bytes out of uTLS, sends them by hand, reads
// one ServerHello record, writes a bare dispatch byte in its own TCP segment,
// and then runs a hand-rolled ChaCha20 stream dressed as application data.
// There is no ChangeCipherSpec, no Finished, no certificate — nothing that
// survives a stateful TLS parser.
//
// Here the handshake is genuine end to end. What an observer sees is a TLS 1.3
// session to a donor name, and it is one, right down to the record lengths.
// Authentication rides in the 32 bytes of session_id that every ClientHello
// already carries, and the server proves itself through the certificate's
// signature field during the handshake, at no cost in packets.

// b1Version is the client version advertised in the session_id payload. The
// server compares it against its MinClientVer policy.
//
// Kept next to the code that sends it rather than derived from the build's
// version string: this is a wire field with a policy attached on the other
// side, and it should change deliberately.
var b1Version = [3]byte{1, 3, 27}

// errB1NoAuthKey guards the certificate callback against running before the
// key it needs exists.
var errB1NoAuthKey = errors.New("reality b1: certificate check ran before the auth key was derived")

// connectB1 performs the whole B1 client sequence and returns the caller's
// stream.
//
// The steps that look like they could be reordered cannot:
//
//   - session_id is sealed over the marshalled ClientHello, so the ClientHello
//     has to be marshalled first, with the field zeroed.
//   - The certificate MAC is checked inside the handshake, so the key for it has
//     to be derived before the handshake starts.
//   - The binding record is the first application data, so it goes after the
//     handshake and before smux.
func (r *REALITYStrategy) connectB1(ctx context.Context, tcpConn net.Conn, dest string, deadline time.Time, secret []byte) (net.Conn, error) {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}

	// authKey is only known after the ClientHello is built, but the callback
	// that needs it has to be installed before the connection is created —
	// uTLS does not expose its config afterwards. The closure reads the
	// variable, which sealSessionID fills below, well before the handshake that
	// invokes the callback.
	var authKey []byte

	fp, _ := customtls.LookupFingerprint(r.fingerprint)
	cfg := &utls.Config{
		ServerName: host,
		MinVersion: utls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		// The chain is not validated, and it is not meant to be: the
		// certificate is self-signed and the server proves itself through the
		// MAC in its signature field instead. VerifyPeerCertificate is what
		// makes that a real check rather than an absent one.
		InsecureSkipVerify: true,
		// Checked during the handshake, so a server that cannot prove itself
		// never sees a single byte of application data.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(authKey) == 0 {
				// Unreachable unless the sequence below is reordered. Fail
				// closed rather than verify against an empty key.
				return errB1NoAuthKey
			}
			return customtls.VerifyCertHMAC(rawCerts, authKey)
		},
	}

	uconn, err := customtls.NewUConn(tcpConn, cfg, fp, 0) // paddingLen 0: B1 sends no padding extension at all
	if err != nil {
		return nil, fmt.Errorf("reality b1: build client: %w", err)
	}

	authKey, err = r.sealSessionID(uconn, secret)
	if err != nil {
		return nil, err
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality b1: handshake: %w", err)
	}

	// Every browser profile carries renegotiation_info, and uTLS turns that
	// extension into config.Renegotiation = RenegotiateOnceAsClient every time
	// it applies the config — which HandshakeContext does. crypto/tls then
	// refuses ExportKeyingMaterial outright, and the whole binding goes with it.
	//
	// The flag is read when ConnectionState() is built, so this is the one point
	// where clearing it sticks: after the last ApplyConfig, before the exporter
	// is asked for. Doing it earlier is silently undone.
	//
	// It costs nothing on the wire. uTLS emits renegotiation_info regardless of
	// this setting, so the ClientHello bytes — and the JA3 and JA4 computed from
	// them — do not move. TLS 1.3 has no renegotiation to give up anyway.
	cfg.Renegotiation = utls.RenegotiateNever

	state := uconn.ConnectionState()
	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		return nil, fmt.Errorf("reality b1: %w", err)
	}

	// proof_c and the dispatch byte travel together inside one encrypted record.
	// The dispatch byte used to go out on its own, unencrypted, in its own TCP
	// segment — signature #1 from the improvement plan.
	if err := customtls.WriteClientBinding(uconn, secret, ekm, protocol.TypeMux); err != nil {
		return nil, fmt.Errorf("reality b1: client binding: %w", err)
	}

	// The server's clock hint. Read but not waited on in any meaningful sense:
	// it is already in flight by the time we look, because the server writes it
	// without waiting for anything from us.
	if srvTime, err := customtls.ReadServerTime(uconn); err != nil {
		// Not fatal. The correction is a hint for the next connection, and this
		// one is already authenticated by the certificate MAC.
		log.Debug("REALITY B1: no server time: %v", err)
	} else {
		r.clockOffset.Observe(srvTime)
		log.Debug("REALITY B1: clock offset now %v", r.clockOffset.Offset())
	}

	// Silent session: no keepalive sent, none expected. See
	// mux.SmuxSilentConfig for why the ten-second NOP is a signal and why
	// jittering it would only move that signal rather than remove it. Safe
	// without negotiation because B1 has never shipped - both ends of any B1
	// session are this build.
	sess, err := smux.Client(uconn, mux.SmuxSilentConfig())
	if err != nil {
		return nil, fmt.Errorf("reality b1: smux client: %w", err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("reality b1: first mux stream: %w", err)
	}

	// The handshake deadline covered the handshake. The stream outlives it —
	// it is a live tunnel, not a bounded exchange — and callers such as
	// pool.PooledRelay manage their own per-operation deadlines.
	_ = deadline
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		log.Debug("REALITY B1: clearing deadline failed: %v", err)
	}

	return &realityConn{Conn: stream, sess: sess, tlsConn: uconn, tcpConn: tcpConn}, nil
}

// sealSessionID runs the ClientHello patch sequence and returns the connection's
// auth key, which is also the key for the certificate MAC.
//
// The order here is load-bearing and the reason is not obvious. uTLS marshals
// the ClientHello again inside HandshakeContext, so a patch written straight
// into Hello.Raw would be overwritten. Marshalling reads session_id from
// Hello.SessionId, so patching the field and letting uTLS re-marshal is what
// actually gets our bytes onto the wire.
//
// That leaves one requirement: the re-marshal must reproduce every other byte
// exactly, or the AAD the server computes will not match the one we sealed
// against. It does — GREASE ECH caches its payload under a sync.Once, which is
// what makes this safe for the Firefox profile — and the length check below is
// the cheap runtime guard against that ceasing to be true.
func (r *REALITYStrategy) sealSessionID(uconn *utls.UConn, secret []byte) ([]byte, error) {
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality b1: build handshake state: %w", err)
	}
	hello := uconn.HandshakeState.Hello

	eph, err := customtls.SelectClientEphemeral(uconn.HandshakeState.State13.KeyShareKeys)
	if err != nil {
		// A profile with no X25519 key share cannot do B1 at all. The Android
		// OkHttp profile is one of these.
		return nil, fmt.Errorf("reality b1: fingerprint %q: %w", r.fingerprint, err)
	}

	hello.SessionId = make([]byte, customtls.AuthSessionIDLen)
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("reality b1: marshal clienthello: %w", err)
	}
	aad := make([]byte, len(hello.Raw))
	copy(aad, hello.Raw)

	payload := customtls.AuthPayload{
		Version: b1Version,
		// Advertised unconditionally, both of them. These say what this client
		// can cope with, not what it will do, so there is nothing to configure
		// and nothing to coordinate with the server's rollout.
		Flags:   customtls.AuthFlagExporterBinding | customtls.AuthFlagReshapeCapable,
		Time:    uint32(r.clockOffset.Now().Unix()),
		ShortID: customtls.ShortIDFor(secret),
	}

	sid, err := customtls.SealSessionID(eph, r.serverStaticPub, aad, hello.Random, payload)
	if err != nil {
		return nil, fmt.Errorf("reality b1: seal session_id: %w", err)
	}
	hello.SessionId = sid[:]

	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("reality b1: remarshal clienthello: %w", err)
	}
	if len(hello.Raw) != len(aad) {
		// Cheap insurance against a uTLS change making the re-marshal
		// non-reproducible. If it ever fires, the symptom without it would be
		// "the server sometimes does not authorize me", with nothing in the logs.
		return nil, fmt.Errorf("reality b1: clienthello changed length across marshals (%d -> %d)", len(aad), len(hello.Raw))
	}

	authKey, err := customtls.ClientAuthKey(eph, r.serverStaticPub, hello.Random)
	if err != nil {
		return nil, fmt.Errorf("reality b1: derive auth key: %w", err)
	}
	return authKey, nil
}
