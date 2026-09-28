//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"
	"unsafe"
)

const (
	recordHeaderLen = 5
	// maxCiphertextLen is the TLS 1.3 limit on a record's encrypted payload
	// (RFC 8446, section 5.2).
	maxCiphertextLen = 16384 + 256
	// maxSettleRounds caps the settle loop. Each round either finishes a
	// split record or processes what is buffered, so a handful is plenty.
	maxSettleRounds = 64
)

// settleReadTimeout bounds the wait for the tail of a record that crypto/tls
// has only partly read. A peer writes a record in one go, so the tail is
// already in flight; this only guards against a peer that stalls mid-record.
// A variable so tests can shorten it.
var settleReadTimeout = 2 * time.Second

// tlsBuffers points into the receive-side buffers of a *tls.Conn:
//
//	rawInput - ciphertext read off the socket, starting at a record header;
//	input    - decrypted application data not yet returned by Read;
//	hand     - decrypted handshake bytes not yet processed.
//
// The kernel never sees any of it: once TLS_RX is set it decrypts from the
// socket read position with the sequence number it was given.
type tlsBuffers struct {
	rawInput *bytes.Buffer
	input    *bytes.Reader
	hand     *bytes.Buffer
}

// tlsReceiveBuffers locates the receive buffers by reflection. A field that is
// missing or has changed type means crypto/tls internals moved; kTLS must not
// be enabled then, since there is no way to tell whether input is buffered.
func tlsReceiveBuffers(conn *tls.Conn) (*tlsBuffers, error) {
	v := reflect.ValueOf(conn).Elem()
	field := func(name string, typ reflect.Type) (unsafe.Pointer, error) {
		f := v.FieldByName(name)
		if !f.IsValid() || f.Type() != typ {
			return nil, fmt.Errorf("crypto/tls.Conn field %q missing or not %v", name, typ)
		}
		return unsafe.Pointer(f.UnsafeAddr()), nil
	}
	raw, err := field("rawInput", reflect.TypeFor[bytes.Buffer]())
	if err != nil {
		return nil, err
	}
	in, err := field("input", reflect.TypeFor[bytes.Reader]())
	if err != nil {
		return nil, err
	}
	hand, err := field("hand", reflect.TypeFor[bytes.Buffer]())
	if err != nil {
		return nil, err
	}
	return &tlsBuffers{
		rawInput: (*bytes.Buffer)(raw),
		input:    (*bytes.Reader)(in),
		hand:     (*bytes.Buffer)(hand),
	}, nil
}

func (b *tlsBuffers) empty() bool {
	return b.rawInput.Len() == 0 && b.input.Len() == 0 && b.hand.Len() == 0
}

// restore puts application data drained by settleReceiveBuffers back into the
// *tls.Conn, so a caller that falls back to userspace TLS still reads it.
// settleReceiveBuffers only returns data once input is empty, so nothing that
// was there is overwritten.
func (b *tlsBuffers) restore(pending []byte) {
	if len(pending) > 0 && b.input.Len() == 0 {
		b.input.Reset(pending)
	}
}

// settleReceiveBuffers brings the receive side of tlsConn to a point where the
// next unread byte on the socket is the first byte of a record and nothing is
// left in crypto/tls buffers. Records already buffered are processed by
// crypto/tls itself (a NewSessionTicket goes to the session cache, a KeyUpdate
// updates the traffic secret); a record split between rawInput and the socket
// is completed by reading exactly its missing bytes, never more. Application
// data decrypted along the way is returned as pending.
//
// It is a no-op, touching neither the socket nor the deadlines, when the
// buffers are already empty. Otherwise it leaves no read deadline set on
// tlsConn.
func settleReceiveBuffers(tlsConn *tls.Conn, b *tlsBuffers) (pending []byte, err error) {
	if b.empty() {
		return nil, nil
	}
	defer tlsConn.SetReadDeadline(time.Time{})

	buf := make([]byte, 16384)
	past := time.Unix(1, 0)
	for range maxSettleRounds {
		// Process every complete record already buffered. With the deadline in
		// the past crypto/tls cannot read the socket, and a timeout is not
		// sticky in crypto/tls, so the conn stays usable.
		for {
			if err := tlsConn.SetReadDeadline(past); err != nil {
				return pending, err
			}
			n, err := tlsConn.Read(buf)
			pending = append(pending, buf[:n]...)
			if err == nil {
				continue
			}
			if isTimeout(err) {
				break
			}
			if errors.Is(err, io.EOF) {
				// close_notify: nothing follows it, the kernel will read EOF.
				return pending, checkSettled(b)
			}
			return pending, err
		}

		raw := b.rawInput.Bytes()
		if len(raw) == 0 {
			return pending, checkSettled(b)
		}
		// What is left is the head of one record whose tail is still on
		// the socket (or in a wrapper under tlsConn). Fetch exactly the tail.
		need := recordHeaderLen - len(raw)
		if len(raw) >= recordHeaderLen {
			n := int(raw[3])<<8 | int(raw[4])
			if n > maxCiphertextLen {
				return pending, fmt.Errorf("buffered record length %d exceeds TLS limit", n)
			}
			need = recordHeaderLen + n - len(raw)
		}
		under := tlsConn.NetConn()
		if err := under.SetReadDeadline(time.Now().Add(settleReadTimeout)); err != nil {
			return pending, err
		}
		tail := make([]byte, need)
		n, err := io.ReadFull(under, tail)
		// Whatever was read belongs to crypto/tls, success or not.
		b.rawInput.Write(tail[:n])
		if err != nil {
			return pending, fmt.Errorf("reading tail of a split record: %w", err)
		}
	}
	return pending, errors.New("buffered TLS input did not settle")
}

func checkSettled(b *tlsBuffers) error {
	if !b.empty() {
		return fmt.Errorf("TLS input left buffered (raw=%d input=%d hand=%d)",
			b.rawInput.Len(), b.input.Len(), b.hand.Len())
	}
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
