package strategy

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// captureConn records everything written to it and never yields reads. It also
// implements the deadline setters as no-ops, which the data-layer wrap and
// protocol.WriteDispatch both call. writeOnlyConn cannot be used here because it
// embeds a nil net.Conn and would panic on SetWriteDeadline.
type captureConn struct {
	buf []byte
}

func (c *captureConn) Write(p []byte) (int, error) { c.buf = append(c.buf, p...); return len(p), nil }
func (c *captureConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *captureConn) Close() error                { return nil }
func (c *captureConn) LocalAddr() net.Addr         { return nil }
func (c *captureConn) RemoteAddr() net.Addr        { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// allApplicationData reports whether wire is a sequence of well-formed TLS
// records that are all Application Data (type 0x17) with no trailing bytes, and
// returns the body length of the first record. A lone cleartext dispatch byte
// (an invalid TLS record type such as 0x08) makes it return false: that is the
// one-line signature S5 removes.
func allApplicationData(wire []byte) (bool, int) {
	firstBody := -1
	for len(wire) > 0 {
		if len(wire) < 5 || wire[0] != 0x17 {
			return false, firstBody
		}
		l := int(binary.BigEndian.Uint16(wire[3:5]))
		if 5+l > len(wire) {
			return false, firstBody
		}
		if firstBody < 0 {
			firstBody = l
		}
		wire = wire[5+l:]
	}
	return firstBody >= 0, firstBody
}

// TestS5DispatchCarriedInsideEncryption asserts the smux discriminator reaches
// the wire as an encrypted Application Data record, not as the bare byte the old
// code wrote in the clear after ServerHello. The broken-order subtest is the
// red-against-broken control (verification rule 1): it reproduces the pre-fix
// write order and confirms the same invariant flags it.
func TestS5DispatchCarriedInsideEncryption(t *testing.T) {
	t.Parallel()

	cp, _ := negotiate(t, []byte("shared-secret"))

	// Fixed (production) order: wrapDataLayer's v2 conn first, then the dispatch
	// through it. NewRealityDataConnV2(_, cp, true) is exactly what wrapDataLayer
	// returns on the v2 path, so this is the real client sequence.
	fixed := &captureConn{}
	dc, err := NewRealityDataConnV2(fixed, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteDispatch(dc, protocol.TypeMux); err != nil {
		t.Fatal(err)
	}
	ok, firstBody := allApplicationData(fixed.buf)
	if !ok {
		t.Fatalf("fixed path put a non-Application-Data byte on the wire: % x", fixed.buf)
	}

	// Rule 8: the first data record used to be the smux cmdSYN (an 8-byte frame);
	// now it is the 1-byte dispatch. Measure both so the histogram note is not a
	// guess. Both are single-valued and both are type 0x17.
	synLike := &captureConn{}
	sdc, err := NewRealityDataConnV2(synLike, cp, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdc.Write(make([]byte, 8)); err != nil { // smux SYN frame size
		t.Fatal(err)
	}
	_, synBody := allApplicationData(synLike.buf)
	t.Logf("S5 rule-8 histogram: first data record body %d bytes (was smux SYN %d bytes); wire %d bytes; both single-valued, both type 0x17",
		firstBody, synBody, len(fixed.buf))

	// Broken (pre-fix) order: dispatch in the clear, then wrap. The invariant
	// must reject it, and the wire must start with the bare discriminator.
	broken := &captureConn{}
	if err := protocol.WriteDispatch(broken, protocol.TypeMux); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRealityDataConnV2(broken, cp, true); err != nil {
		t.Fatal(err)
	}
	if leaked, _ := allApplicationData(broken.buf); leaked {
		t.Fatal("pre-fix cleartext dispatch was NOT caught by the invariant; the test proves nothing")
	}
	if len(broken.buf) == 0 || broken.buf[0] != protocol.TypeMux {
		t.Fatalf("pre-fix wire should start with the bare dispatch 0x%02x, got % x", protocol.TypeMux, broken.buf)
	}
}

// TestS5ServerReadsDispatchFromEncryptedStream reproduces the server's decision
// in internal/server/reality.go handleREALITYSession on the real data-conn
// types: read the discriminator through the wrapped conn and reject anything
// that is not TypeMux. The happy path is the positive control (rule 2); the
// desync path is an old client that wrote the dispatch in the clear before
// wrapping, which the server now reads as a malformed TLS record and refuses,
// instead of falling into handleRawTunnel on it.
func TestS5ServerReadsDispatchFromEncryptedStream(t *testing.T) {
	t.Parallel()

	t.Run("encrypted TypeMux round-trips", func(t *testing.T) {
		cp, sp := negotiate(t, []byte("shared-secret"))
		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		cdc, err := NewRealityDataConnV2(clientRaw, cp, true)
		if err != nil {
			t.Fatal(err)
		}
		sdc, err := NewRealityDataConnV2(serverRaw, sp, false)
		if err != nil {
			t.Fatal(err)
		}

		werr := make(chan error, 1)
		go func() { werr <- protocol.WriteDispatch(cdc, protocol.TypeMux) }()

		got, err := protocol.ReadDispatch(sdc)
		if err != nil {
			t.Fatalf("server failed to read encrypted dispatch: %v", err)
		}
		if got != protocol.TypeMux {
			t.Fatalf("server read 0x%02x, want TypeMux 0x%02x", got, protocol.TypeMux)
		}
		if err := <-werr; err != nil {
			t.Fatalf("client write: %v", err)
		}
	})

	t.Run("cleartext (desynced) dispatch is refused", func(t *testing.T) {
		_, sp := negotiate(t, []byte("shared-secret"))
		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		// Old client: bare dispatch byte followed by whatever it wrapped. The
		// server decrypts the first "record" and its type byte is 0x08, not 0x17.
		go func() {
			clientRaw.Write(append([]byte{protocol.TypeMux}, make([]byte, 32)...))
		}()

		sdc, err := NewRealityDataConnV2(serverRaw, sp, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := protocol.ReadDispatch(sdc); err == nil {
			t.Fatalf("server accepted a cleartext desynced dispatch (0x%02x); it must fail so the handler closes instead of opening a raw tunnel", got)
		}
	})
}
