package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/xtaci/smux"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	gostx509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

const GosuslugiSNI = "www.gosuslugi.ru"
const GOSTTLS13StrategyID = "gost_tls13_gosuslugi"

// GOSTTLS13Strategy is an opt-in RFC 9367 TLS 1.3 transport. The endpoint is
// still the configured TiredVPN server; GosuslugiSNI is only sent as SNI.
type GOSTTLS13Strategy struct {
	manager *Manager
	pin     [sha256.Size]byte
	port    int
}

func NewGOSTTLS13Strategy(manager *Manager, pinHex string, port int) (*GOSTTLS13Strategy, error) {
	var s GOSTTLS13Strategy
	if manager == nil {
		return nil, fmt.Errorf("gost_tls13: manager is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("gost_tls13: listener port must be explicitly set to 1..65535")
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(pinHex))
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("gost_tls13: certificate pin must be 64 hexadecimal SHA-256 characters")
	}
	s.manager = manager
	s.port = port
	copy(s.pin[:], decoded)
	return &s, nil
}

func (s *GOSTTLS13Strategy) Name() string         { return "GOST TLS 1.3 (Gosuslugi SNI)" }
func (s *GOSTTLS13Strategy) ID() string           { return GOSTTLS13StrategyID }
func (s *GOSTTLS13Strategy) Priority() int        { return 70 }
func (s *GOSTTLS13Strategy) RequiresServer() bool { return true }
func (s *GOSTTLS13Strategy) Description() string {
	return "Experimental strict GOST TLS 1.3 (RFC 9367), SNI www.gosuslugi.ru; requires server GOST certificate and pinned SHA-256 certificate fingerprint."
}

func (s *GOSTTLS13Strategy) Probe(ctx context.Context, target string) error {
	addr, err := s.serverAddr(ctx)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func (s *GOSTTLS13Strategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	addr, err := s.serverAddr(ctx)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("gost_tls13: TCP dial: %w", err)
	}
	return s.handshakeMux(ctx, raw)
}

func (s *GOSTTLS13Strategy) serverAddr(ctx context.Context) (string, error) {
	endpoint := s.manager.GetServerAddr(ctx)
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("gost_tls13: invalid server endpoint %q: %w", endpoint, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(s.port)), nil
}

// handshakeMux is kept separate so pin verification can use the GOST library's
// raw certificate callback (its verified-chain type differs from crypto/x509).
func (s *GOSTTLS13Strategy) handshakeMux(ctx context.Context, raw net.Conn) (net.Conn, error) {
	config := gosttls.GOSTConfig(&gosttls.Config{
		ServerName:         GosuslugiSNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*gostx509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("gost_tls13: server sent no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if got != s.pin {
				return fmt.Errorf("gost_tls13: server certificate pin mismatch")
			}
			leaf, err := gostx509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("gost_tls13: parse pinned server certificate: %w", err)
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return fmt.Errorf("gost_tls13: pinned server certificate is outside its validity period")
			}
			return nil
		},
	})
	tlsConn := gosttls.Client(raw, config)
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else {
		_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: TLS handshake: %w", err)
	}
	if tlsConn.ConnectionState().Version != gosttls.VersionTLS13 || !isGOSTSuite(tlsConn.ConnectionState().CipherSuite) {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: peer did not negotiate a GOST TLS 1.3 cipher suite")
	}
	if err := protocol.WriteDispatch(tlsConn, protocol.TypeMux); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: mux dispatch: %w", err)
	}
	sess, err := smux.Client(tlsConn, smux.DefaultConfig())
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: smux: %w", err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &gostTLSMuxConn{Conn: stream, sess: sess, raw: raw}, nil
}

type gostTLSMuxConn struct {
	net.Conn
	sess *smux.Session
	raw  net.Conn
}

func (c *gostTLSMuxConn) Close() error {
	e1 := c.Conn.Close()
	e2 := c.sess.Close()
	e3 := c.raw.Close()
	if e1 != nil {
		return e1
	}
	if e2 != nil {
		return e2
	}
	return e3
}

func isGOSTSuite(id uint16) bool { return id >= 0xC103 && id <= 0xC106 }

var _ io.ReadWriteCloser = (*gostTLSMuxConn)(nil)
