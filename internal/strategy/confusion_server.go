package strategy

import (
	"net"
	"sync"
)

// The server half of the confusion wire.
//
// Everything here runs before the server has said a word. ReadConfusionRequest
// only parses; MatchConfusionClientMarker decides; and until a secret matches,
// nothing is dialled, no address is parsed out of the packet and no byte goes
// back to the peer. That ordering is the fix: in 1.10.0 the server answered
// "TIRED" and opened a TCP relay to an address taken straight out of an
// unauthenticated packet.

// ReadConfusionRequest pulls the opening carrier off conn, starting from bytes
// the dispatcher already peeked.
//
// It returns the parsed carrier, whatever was read past it, and everything
// consumed - the last one so a caller that decides this is not a confusion
// client can put those bytes back in front of the next detector instead of
// swallowing them.
func ReadConfusionRequest(conn net.Conn, pre []byte) (*ConfusionCarrier, []byte, []byte, error) {
	return ReadConfusionCarrier(conn, pre, ParseConfusionRequest)
}

// ConfusionServerConn is the server end: the answering carrier on the first
// write, the sealed record layer for everything else.
type ConfusionServerConn struct {
	net.Conn // the raw socket

	req    *ConfusionCarrier
	secret []byte
	sealed *ConfusionConn

	wMu         sync.Mutex
	sentCarrier bool
}

// NewConfusionServerConn builds the server end for an already-authenticated
// request. body is what remained of the carrier after the marker, and leftover
// is what the carrier reader over-read; both are sealed frames from the client
// and are handed to the record layer in order.
func NewConfusionServerConn(raw net.Conn, req *ConfusionCarrier, secret []byte, body, leftover []byte) (*ConfusionServerConn, error) {
	pre := make([]byte, 0, len(body)+len(leftover))
	pre = append(pre, body...)
	pre = append(pre, leftover...)

	pb := &confusionPushback{Conn: raw, pre: pre}
	sealed, err := NewConfusionConn(pb, secret, req.Nonce, req.Variant, false)
	if err != nil {
		return nil, err
	}

	return &ConfusionServerConn{
		Conn:   raw,
		req:    req,
		secret: secret,
		sealed: sealed,
	}, nil
}

// Write seals p and, on the first call, wraps the first sealed frame in the
// answering carrier - a DNS response to a DNS query, a 200 to a POST, a
// KEX_ECDH_REPLY to a KEX_ECDH_INIT, a SASL challenge to a SASL initial
// response. The marker inside it is what proves to the client that the peer
// holds the secret too, and it replaces the constant "TIRED" that used to
// identify this server to anyone who sent five bytes.
func (c *ConfusionServerConn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	if c.sentCarrier {
		return c.sealed.Write(p)
	}

	frames := c.sealed.SealFrames(p)
	first, rest := splitFirstConfusionFrame(frames)

	marker := ConfusionServerMarker(c.secret, c.req.Nonce, c.req.Variant)
	if len(marker) == 0 {
		return 0, errConfusionNoSecret
	}
	carrier, err := BuildConfusionResponse(c.req, marker, first)
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

// Read is a byte stream over the sealed frames.
func (c *ConfusionServerConn) Read(p []byte) (int, error) { return c.sealed.Read(p) }

// ReadFrame returns one sealed message with the boundary the client wrote,
// which is what the proxy relay needs to recognise a control message.
func (c *ConfusionServerConn) ReadFrame() ([]byte, error) { return c.sealed.ReadFrame() }
