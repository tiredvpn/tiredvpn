package strategy

import (
	"context"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	mathrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ProtocolConfusionStrategy crafts packets that look like different protocols
// to different parsers (DPI vs real server).
//
// The secret is not decoration here. It keys the marker the server
// authenticates on and the record layer that carries every byte after it, so a
// strategy built without one cannot connect at all - which is why registration
// is gated on having one, exactly like the other fifteen strategies.
type ProtocolConfusionStrategy struct {
	manager       *Manager // Reference to Manager for IPv6/IPv4 support
	confusionType ConfusionType
	secret        []byte
}

// ConfusionType defines which protocol confusion to use
type ConfusionType int

const (
	// ConfusionDNSoverTLS - carried in an EDNS0 option of a DNS-over-TCP query
	ConfusionDNSoverTLS ConfusionType = iota

	// ConfusionHTTPoverTLS - carried in the body of an HTTP/1.1 POST
	ConfusionHTTPoverTLS

	// ConfusionSSHoverTLS - carried in an SSH string inside a binary packet
	ConfusionSSHoverTLS

	// ConfusionSMTPoverTLS - carried in a SASL initial response
	ConfusionSMTPoverTLS

	// ConfusionMultiLayer - carried in a gRPC-Web message over HTTP/1.1
	ConfusionMultiLayer
)

// errConfusionServerAuth is what a client reports when the answering carrier
// does not carry the marker only our server can produce. It covers both an
// impostor and an old server that still answers with the literal "TIRED".
var errConfusionServerAuth = errors.New("confusion: server did not prove the secret")

// errConfusionNoSecret guards the one path that could otherwise put an
// unauthenticated confusion connection on the wire.
var errConfusionNoSecret = errors.New("confusion: no secret configured")

// NewProtocolConfusionStrategy creates a new confusion strategy
// manager is required for IPv6/IPv4 transport layer support
func NewProtocolConfusionStrategy(manager *Manager, confType ConfusionType, secret []byte) *ProtocolConfusionStrategy {
	return &ProtocolConfusionStrategy{
		manager:       manager,
		confusionType: confType,
		secret:        secret,
	}
}

func (s *ProtocolConfusionStrategy) Name() string {
	names := map[ConfusionType]string{
		ConfusionDNSoverTLS:  "Protocol Confusion (DNS)",
		ConfusionHTTPoverTLS: "Protocol Confusion (HTTP)",
		ConfusionSSHoverTLS:  "Protocol Confusion (SSH)",
		ConfusionSMTPoverTLS: "Protocol Confusion (SMTP)",
		ConfusionMultiLayer:  "Protocol Confusion (Multi-Layer)",
	}
	return names[s.confusionType]
}

func (s *ProtocolConfusionStrategy) ID() string {
	return "confusion_" + string(rune('0'+s.confusionType))
}

func (s *ProtocolConfusionStrategy) Priority() int {
	return 25
}

func (s *ProtocolConfusionStrategy) Description() string {
	return "Crafts packets that appear as safe protocols to DPI but are parsed differently by server"
}

func (s *ProtocolConfusionStrategy) RequiresServer() bool {
	return true // Server must understand the confusion format
}

func (s *ProtocolConfusionStrategy) Probe(ctx context.Context, target string) error {
	// Lightweight reachability check: a plain TCP connect (no confusion
	// preamble, no TLS) against the same address Connect uses. This keeps
	// ProbeAll's parallel fan-out cheap and avoids a thundering herd of full
	// handshakes hammering server-side admission control.
	serverAddr := s.manager.GetServerAddr(ctx)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *ProtocolConfusionStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	secret := dialSecret(ctx, s.secret)
	if len(secret) == 0 {
		return nil, errConfusionNoSecret
	}

	serverAddr := s.manager.GetServerAddr(ctx)
	log.Debug("Protocol Confusion: Connecting to %s (raw TCP, no TLS)", serverAddr)

	// Confusion operates on raw TCP — the confused carrier IS the transport
	// layer. No TLS wrapper; DPI sees a well-formed DNS/HTTP/SSH/SMTP/gRPC-Web
	// exchange, the server sees a keyed marker it can authenticate.
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	cc, err := NewConfusedConn(conn, s.confusionType, secret)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

// ConfusedConn wraps connection with protocol confusion
var confusionDomains = []string{
	"yandex.ru",
	"baidu.com",
	"aparat.com",
	"qq.com",
	"mail.ru",
	"digikala.com",
}

func getRandomConfusionDomain() string {
	return confusionDomains[mathrand.Intn(len(confusionDomains))]
}

// encodeDNSName encodes a dotted domain into DNS label format.
func encodeDNSName(domain string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			label := domain[start:i]
			if len(label) > 0 {
				out = append(out, byte(len(label)))
				out = append(out, []byte(label)...)
			}
			start = i + 1
		}
	}
	out = append(out, 0x00) // root label
	return out
}

// confusionPushback lets the carrier reader hand bytes it over-read back to the
// record layer that comes after it.
type confusionPushback struct {
	net.Conn
	pre []byte
}

func (c *confusionPushback) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		if len(c.pre) == 0 {
			c.pre = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

// ConfusedConn is the client end of the confusion wire.
//
// The first write goes out inside the carrier; the first read expects the
// answering carrier and refuses to continue unless it proves the secret.
// Everything after that is the sealed record layer, so there is no mode where
// user bytes reach the socket unencrypted - which is what the old rawMode
// switch amounted to, and why it is gone.
type ConfusedConn struct {
	net.Conn // the raw socket

	variant byte
	secret  []byte
	nonce   [ConfusionNonceLen]byte

	pb     *confusionPushback
	sealed *ConfusionConn

	wMu         sync.Mutex
	sentCarrier bool

	rMu        sync.Mutex
	gotCarrier bool
}

// NewConfusedConn creates a confused connection over an already-dialled socket.
func NewConfusedConn(conn net.Conn, confType ConfusionType, secret []byte) (*ConfusedConn, error) {
	if len(secret) == 0 {
		return nil, errConfusionNoSecret
	}
	nonce, err := NewConfusionNonce()
	if err != nil {
		return nil, err
	}

	variant := byte(confType)
	pb := &confusionPushback{Conn: conn}
	sealed, err := NewConfusionConn(pb, secret, nonce[:], variant, true)
	if err != nil {
		return nil, err
	}

	return &ConfusedConn{
		Conn:    conn,
		variant: variant,
		secret:  secret,
		nonce:   nonce,
		pb:      pb,
		sealed:  sealed,
	}, nil
}

// Write seals p and, on the first call, wraps the first sealed frame in the
// carrier for this variant.
func (c *ConfusedConn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	if c.sentCarrier {
		return c.sealed.Write(p)
	}

	frames := c.sealed.SealFrames(p)
	first, rest := splitFirstConfusionFrame(frames)

	marker := ConfusionClientMarker(c.secret, c.nonce[:], c.variant)
	if len(marker) == 0 {
		return 0, errConfusionNoSecret
	}
	carrier, err := BuildConfusionRequest(c.variant, c.nonce[:], marker, first)
	if err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(carrier); err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	c.sentCarrier = true
	return len(p), nil
}

// Read consumes the answering carrier once, verifies the server's marker, and
// then reads the sealed stream.
func (c *ConfusedConn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	if !c.gotCarrier {
		if err := c.readServerCarrier(); err != nil {
			c.rMu.Unlock()
			return 0, err
		}
		c.gotCarrier = true
	}
	c.rMu.Unlock()

	return c.sealed.Read(p)
}

// ReadFrame returns one sealed message, preserving the boundary the peer wrote.
func (c *ConfusedConn) ReadFrame() ([]byte, error) {
	c.rMu.Lock()
	if !c.gotCarrier {
		if err := c.readServerCarrier(); err != nil {
			c.rMu.Unlock()
			return nil, err
		}
		c.gotCarrier = true
	}
	c.rMu.Unlock()

	return c.sealed.ReadFrame()
}

func (c *ConfusedConn) readServerCarrier() error {
	carrier, leftover, _, err := ReadConfusionCarrier(c.Conn, nil, func(b []byte) (*ConfusionCarrier, error) {
		return ParseConfusionResponse(c.variant, b)
	})
	if err != nil {
		if errors.Is(err, ErrConfusionNotCarrier) {
			// A server that answers in some other shape is not ours. Say so
			// rather than handing its bytes up as if they were payload, which
			// is what the old fall-through did.
			return errConfusionServerAuth
		}
		return err
	}

	want := ConfusionServerMarker(c.secret, c.nonce[:], c.variant)
	if len(want) == 0 || len(carrier.Body) < len(want) || !hmac.Equal(carrier.Body[:len(want)], want) {
		return errConfusionServerAuth
	}

	// carrier.Body and leftover both point into the reader's buffer, so the
	// remainder is copied out rather than appended in place.
	rest := make([]byte, 0, len(carrier.Body)-len(want)+len(leftover))
	rest = append(rest, carrier.Body[len(want):]...)
	rest = append(rest, leftover...)
	c.pb.pre = rest
	return nil
}

// splitFirstConfusionFrame peels one sealed frame off the front. Only the first
// frame rides inside the carrier; anything beyond it follows on the wire, where
// it is indistinguishable from the rest of the sealed stream.
func splitFirstConfusionFrame(frames []byte) ([]byte, []byte) {
	if len(frames) < 2 {
		return frames, nil
	}
	n := int(binary.BigEndian.Uint16(frames[:2]))
	if 2+n > len(frames) {
		return frames, nil
	}
	return frames[:2+n], frames[2+n:]
}

// AllConfusionTypes returns all available confusion strategies
// manager is required for IPv6/IPv4 transport layer support
func AllConfusionTypes(manager *Manager, secret []byte) []*ProtocolConfusionStrategy {
	types := []ConfusionType{
		ConfusionDNSoverTLS,
		ConfusionHTTPoverTLS,
		ConfusionSSHoverTLS,
		ConfusionSMTPoverTLS,
		ConfusionMultiLayer,
	}

	strategies := make([]*ProtocolConfusionStrategy, len(types))
	for i, t := range types {
		strategies[i] = NewProtocolConfusionStrategy(manager, t, secret)
	}
	return strategies
}
