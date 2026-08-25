package tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"
)

// Exporter binding: proving the client is ours, at zero extra round trips.
//
// The TLS exporter (RFC 8446 §7.5) yields the same keying material on both ends
// only if they completed the same handshake with the same keys. A MITM that
// terminates TLS gets different material on each side and cannot produce the
// HMAC over it, whatever certificate it presents.
//
// Direction matters here. proof_c authenticates the client to the server, and
// it stays: it is the only thing standing between a leaked server static key
// and an attacker impersonating any client, and it costs nothing because the
// client speaks first anyway.
//
// The other direction — proving the server to the client — is NOT done here.
// It is cert-HMAC (epic B1.5, task 011): the server signs its certificate and
// the client checks it inside VerifyPeerCertificate, during the handshake, for
// zero extra packets. A synchronous proof_s would have forced the client to
// wait a full round trip before passing user traffic, on every CONNECT, and the
// pool does not currently reuse connections, so that is a per-request cost.
//
// Ordering consequence worth stating plainly: until cert-HMAC lands, nothing in
// this package authenticates the server to the client. B1 must not reach
// production ahead of B1.5 task 011 without something else filling that gap.
//
// Two riders come along with the client record:
//
//   - The dispatch byte moves inside an encrypted record. Today it goes out as
//     a bare 0x08 in its own TCP segment — signature #1 from the improvement
//     plan, and the single most obvious thing about our flow.
//   - The padding gives a place for Vision-style shaping later without another
//     format change.
const (
	// BindingExporterLabel is the RFC 5705 / RFC 8446 §7.5 exporter label. The
	// "EXPORTER-" prefix is the convention for non-IANA-registered labels.
	BindingExporterLabel = "EXPORTER-tiredvpn-reality-bind"

	// BindingExporterLen is how many bytes of keying material we export.
	BindingExporterLen = 32

	// proofLen is the size of an HMAC-SHA256 proof.
	proofLen = 32

	// minBindingPad and maxBindingPad bound the random padding on each record.
	// The maximum is also enforced on read: a peer that lies about padLen must
	// not be able to make us allocate an arbitrary buffer.
	//
	// The floor is 200 rather than a token 64: at the bottom of the old range
	// the whole record came to 99 bytes, which is small enough to stand out on
	// its own. Raising the floor costs nothing - the padding is discarded on
	// arrival either way - and it is the one part of this record's shape we can
	// fix without touching the protocol.
	minBindingPad = 200
	maxBindingPad = 512

	// dirClientToServer is mixed into the proof for domain separation. There is
	// only one proof now that the server side moved to cert-HMAC, but the tag
	// stays: it keeps this HMAC from colliding with any other use of the same
	// secret and exporter, and removing it would be a wire format change for no
	// gain.
	dirClientToServer = "c2s"
)

// ErrBindingMismatch reports that the peer's proof did not verify.
//
// It is deliberately distinguishable from an I/O error: on the server, a
// mismatch means "not one of ours, serve the decoy website over this same TLS
// connection", while a read error means "the connection died, just close". A
// server that conflated the two would either drop real probes or serve the
// decoy to a truncated connection, and both are observable.
var ErrBindingMismatch = errors.New("reality binding: proof mismatch")

// ErrBindingPadTooLarge reports a padLen outside the permitted range.
var ErrBindingPadTooLarge = errors.New("reality binding: padding length exceeds the maximum")

// Exporter is the subset of a TLS connection state this file needs. Both
// crypto/tls.ConnectionState and utls.ConnectionState satisfy it, which is what
// lets the server (crypto/tls) and the client (uTLS) share this code.
type Exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// ExportBindingKey pulls the binding keying material out of a completed
// handshake. Both sides must call it with the same label and length, which is
// why neither is a parameter.
func ExportBindingKey(e Exporter) ([]byte, error) {
	ekm, err := e.ExportKeyingMaterial(BindingExporterLabel, nil, BindingExporterLen)
	if err != nil {
		return nil, fmt.Errorf("reality binding: export keying material: %w", err)
	}
	if len(ekm) != BindingExporterLen {
		return nil, fmt.Errorf("reality binding: exporter returned %d bytes, want %d", len(ekm), BindingExporterLen)
	}
	return ekm, nil
}

// ClientProof is the value a client sends to prove it shares both the secret
// and the TLS handshake.
func ClientProof(secret, ekm []byte) [proofLen]byte {
	return bindingProof(secret, dirClientToServer, ekm)
}

func bindingProof(secret []byte, dir string, ekm []byte) [proofLen]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(dir))
	mac.Write(ekm)
	var out [proofLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// WriteClientBinding sends the client's first application record:
//
//	[proof_c:32][dispatch:1][padLen:2][pad:padLen]
//
// The client speaks first, as it does in real HTTPS; keeping that order is part
// of not looking unusual.
//
// The whole frame goes out in a single Write so it lands in one TLS record.
// Splitting it would put a distinctive small-record pattern at the head of every
// session, which is the sort of thing this exchange exists to remove.
func WriteClientBinding(w io.Writer, secret, ekm []byte, dispatch byte) error {
	proof := ClientProof(secret, ekm)

	frame := make([]byte, 0, proofLen+1+2+maxBindingPad)
	frame = append(frame, proof[:]...)
	frame = append(frame, dispatch)

	frame, err := appendPadding(frame)
	if err != nil {
		return err
	}
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("reality binding: write client record: %w", err)
	}
	return nil
}

// ReadClientBinding reads and verifies the client's record, returning the
// dispatch byte.
//
// The entire frame is consumed before the proof is checked. That is required,
// not incidental: on a mismatch the caller keeps using this same TLS connection
// to serve the decoy website, so leaving unread padding in the stream would
// corrupt it.
//
// The caller owns the deadline. A peer that sends a header and then stalls will
// block here forever otherwise.
func ReadClientBinding(r io.Reader, secret, ekm []byte) (dispatch byte, err error) {
	head := make([]byte, proofLen+1+2)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, fmt.Errorf("reality binding: read client record: %w", err)
	}
	if err := discardPadding(r, head[proofLen+1:]); err != nil {
		return 0, err
	}

	want := ClientProof(secret, ekm)
	if !hmac.Equal(head[:proofLen], want[:]) {
		return 0, ErrBindingMismatch
	}
	return head[proofLen], nil
}

// WriteServerTime sends the server's one-way clock hint:
//
//	[srvtime:8][padLen:2][pad:padLen]
//
// There is no proof here and the client does not wait for this record. The
// clock correction is a hint for the client's *next* connection — this one has
// already passed the gate — so making it synchronous would buy nothing and cost
// a round trip on every CONNECT.
//
// srvTime is truncated to whole seconds, which is all the client needs and all
// the session_id timestamp can carry.
func WriteServerTime(w io.Writer, srvTime time.Time) error {
	frame := make([]byte, 0, 8+2+maxBindingPad)
	frame = binary.BigEndian.AppendUint64(frame, uint64(srvTime.Unix()))

	frame, err := appendPadding(frame)
	if err != nil {
		return err
	}
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("reality binding: write server time: %w", err)
	}
	return nil
}

// ReadServerTime reads the server's clock hint.
//
// The record carries no proof of its own: it arrives inside a TLS session the
// client has already authenticated via cert-HMAC during the handshake. That
// makes cert-HMAC a precondition, not an optimisation — feeding ClockOffset
// from an unauthenticated session would let anyone push the client's clock far
// enough to lock it out of its own server through MaxTimeDiff.
//
// Callers must treat this as optional. A client that never receives it keeps
// using its own clock, which is the status quo.
func ReadServerTime(r io.Reader) (srvTime time.Time, err error) {
	head := make([]byte, 8+2)
	if _, err := io.ReadFull(r, head); err != nil {
		return time.Time{}, fmt.Errorf("reality binding: read server time: %w", err)
	}
	if err := discardPadding(r, head[8:]); err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(binary.BigEndian.Uint64(head[:8])), 0), nil
}

// appendPadding appends [padLen:2][pad] with padLen drawn uniformly from
// [minBindingPad, maxBindingPad].
func appendPadding(frame []byte) ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(maxBindingPad-minBindingPad+1))
	if err != nil {
		return nil, fmt.Errorf("reality binding: padding length: %w", err)
	}
	padLen := minBindingPad + int(n.Int64())

	frame = binary.BigEndian.AppendUint16(frame, uint16(padLen))
	pad := make([]byte, padLen)
	if _, err := rand.Read(pad); err != nil {
		return nil, fmt.Errorf("reality binding: padding: %w", err)
	}
	return append(frame, pad...), nil
}

// discardPadding reads and drops the padding described by a 2-byte length.
// The cap is checked before allocating, so a peer claiming 65535 bytes gets an
// error rather than a 64 KiB buffer per connection.
func discardPadding(r io.Reader, lenBytes []byte) error {
	padLen := int(binary.BigEndian.Uint16(lenBytes))
	if padLen > maxBindingPad {
		return fmt.Errorf("%w: %d > %d", ErrBindingPadTooLarge, padLen, maxBindingPad)
	}
	if padLen == 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return fmt.Errorf("reality binding: read padding: %w", err)
	}
	return nil
}

// ClockOffset holds the difference between our clock and the server's, learned
// from the server's one-way time record and applied to the unixtime in future
// session_ids.
//
// Held in memory for the process lifetime; persisting it across restarts is out
// of scope and probably unnecessary, since one connection re-learns it.
//
// Only feed this from a session authenticated by cert-HMAC — see ReadServerTime
// for why that is a precondition rather than a nicety.
type ClockOffset struct {
	seconds atomic.Int64
}

// Observe records the offset implied by a server timestamp.
func (c *ClockOffset) Observe(srvTime time.Time) {
	c.seconds.Store(int64(time.Until(srvTime).Round(time.Second) / time.Second))
}

// Now returns the current time corrected by the observed offset. With no
// observation it is plain time.Now.
func (c *ClockOffset) Now() time.Time {
	return time.Now().Add(time.Duration(c.seconds.Load()) * time.Second)
}

// Offset returns the correction currently applied, for logging.
func (c *ClockOffset) Offset() time.Duration {
	return time.Duration(c.seconds.Load()) * time.Second
}
