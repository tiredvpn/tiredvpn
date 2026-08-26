package tun

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// handshakeBase is the 9-byte prefix every response shape starts with:
// [status:1][serverIP:4][clientIP:4].
var handshakeBase = []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2}

// chunkedConn serves payload to the client end of a pipe, cut at the given
// offsets. A read past the end of the payload blocks until the caller's
// deadline, which is what a server that has said all it is going to say looks
// like on the wire.
func chunkedConn(t *testing.T, payload []byte, splits ...int) net.Conn {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	bounds := make([]int, 0, len(splits)+1)
	bounds = append(bounds, splits...)
	bounds = append(bounds, len(payload))

	go func() {
		prev := 0
		for _, b := range bounds {
			if b <= prev || b > len(payload) {
				continue
			}
			if _, err := srv.Write(payload[prev:b]); err != nil {
				return
			}
			prev = b
		}
	}()
	return cli
}

// deadlineErrConn refuses to arm a read deadline. peekHandshakeFlags must
// treat that as "cannot bound this read" and give up rather than read the
// tenth byte unbounded, which against a legacy exit would hang the connect
// until the outer handshake timeout.
type deadlineErrConn struct {
	scriptedConn
	reads int
}

func (c *deadlineErrConn) Read(p []byte) (int, error) {
	c.reads++
	return c.scriptedConn.Read(p)
}

func (c *deadlineErrConn) SetReadDeadline(time.Time) error {
	return errors.New("transport cannot arm a deadline")
}

// dualResponses returns the response shapes an exit may send to a dual-stack
// (v0x04) client, keyed by name. Every one of them carries the dual-stack flag
// and therefore has to be read to completion: a byte left in the stream is
// parsed by the packet loop as [len:4][pkt:N] and kills the session silently.
func dualResponses() map[string][]byte {
	block, _, _ := dualBlock()
	mk := func(flags byte, mid []byte) []byte {
		out := append(append([]byte{}, handshakeBase...), flags)
		out = append(out, mid...)
		return append(out, block...)
	}
	return map[string][]byte{
		// 10-byte flags-only base + 32-byte block.
		"flags-only base":            mk(tunFlagDualStack, nil),
		"flags-only base with probe": mk(tunFlagMTUProbe|tunFlagDualStack, nil),
		// 20-byte v2 base (no seed) + block.
		"v2 base, no seed": mk(tunFlagPortHopping|tunFlagMTUProbe|tunFlagDualStack,
			[]byte{0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x01, 0x00}),
		// 20+seed v2 base + block: the block offset is unknowable until
		// resp[19] has been read.
		"v2 base with seed": mk(tunFlagPortHopping|tunFlagDualStack,
			[]byte{0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x00, 0x04, 's', 'e', 'e', 'd'}),
	}
}

// TestReadHandshakeResponseSplitAtEveryBoundary is the exhaustive version of
// TestReadHandshakeResponseFragmented: every dual-stack response shape, cut at
// every single byte offset. A transport is free to deliver the response in any
// segmentation (TCP segment, TLS record, stego frame), and each shape has three
// separate length decisions in it — the 9-byte prefix, the flags byte, the
// seed-dependent base — so a boundary landing on any of them must still leave
// the stream frame-aligned.
func TestReadHandshakeResponseSplitAtEveryBoundary(t *testing.T) {
	for name, payload := range dualResponses() {
		t.Run(name, func(t *testing.T) {
			for k := 1; k < len(payload); k++ {
				conn := chunkedConn(t, payload, k)
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("split %d: set deadline: %v", k, err)
				}
				resp, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack)
				if err != nil {
					t.Fatalf("split at %d: %v", k, err)
				}
				if n != len(payload) {
					t.Fatalf("split at %d: n = %d, want %d (tail left in the stream)", k, n, len(payload))
				}
				if !bytes.Equal(resp[:n], payload) {
					t.Fatalf("split at %d: resp = %x, want %x", k, resp[:n], payload)
				}
			}
		})
	}
}

// TestReadHandshakeResponseShapesSingleRead pins that every response shape
// parses to the right capabilities when it arrives in one piece, so the
// fragmentation tests above are comparing against a known-good baseline rather
// than against themselves.
func TestReadHandshakeResponseShapesSingleRead(t *testing.T) {
	_, server6, client6 := dualBlock()

	for name, payload := range dualResponses() {
		t.Run(name, func(t *testing.T) {
			conn := &scriptedConn{chunks: [][]byte{payload}}
			resp, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack)
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if n != len(payload) {
				t.Fatalf("n = %d, want %d", n, len(payload))
			}
			caps, ok := parseServerCapabilities(resp, n)
			if !ok || !caps.DualStackEnabled {
				t.Fatalf("dual-stack not detected: %+v ok=%v", caps, ok)
			}
			if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
				t.Errorf("v6 addrs = %s/%s, want %s/%s", caps.ServerIP6, caps.ClientIP6, server6, client6)
			}
		})
	}
}

// TestReadHandshakeResponseV4OnlyShapes checks that a response is read to
// completion for every client version and every split, not just for the
// dual-stack one. Reading only what the first Read happened to return left the
// rest of an extended response in the stream, and the packet loop then parsed
// it as [len:4][pkt:N] - a silent desync of the tunnel.
//
// The client's own version picks the layout: the 14-byte v1 form goes to a
// v0x01 client, the 20+seed v2 form to anything above it. The two are
// indistinguishable by content, which is why the reader is told the version
// rather than guessing.
func TestReadHandshakeResponseV4OnlyShapes(t *testing.T) {
	v1 := append(append([]byte{}, handshakeBase...),
		tunFlagPortHopping, 0xb7, 0x98, 0xb7, 0xfc)
	v2 := append(append([]byte{}, handshakeBase...),
		tunFlagPortHopping, 0xb7, 0x98, 0xb7, 0xfc, 0, 0, 0, 60, 0x01, 0x00)

	for name, tc := range map[string]struct {
		payload []byte
		version byte
	}{
		"legacy 9-byte":         {handshakeBase, tunHandshakeVersion},
		"v1 14-byte":            {v1, 0x01},
		"v2 20-byte":            {v2, tunHandshakeVersion},
		"v2 20-byte, v4 client": {v2, tunHandshakeVersionDualStack},
	} {
		t.Run(name, func(t *testing.T) {
			for k := 1; k < len(tc.payload); k++ {
				conn := chunkedConn(t, tc.payload, k)
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("split %d: set deadline: %v", k, err)
				}
				resp, n, err := readHandshakeResponse(conn, tc.version)
				if err != nil {
					t.Fatalf("split at %d: %v", k, err)
				}
				if n != len(tc.payload) {
					t.Fatalf("split at %d: n = %d, want the whole %d-byte response",
						k, n, len(tc.payload))
				}
				if !bytes.Equal(resp[:n], tc.payload) {
					t.Fatalf("split at %d: response = %x, want %x", k, resp[:n], tc.payload)
				}
			}
		})
	}
}

func TestReadHandshakeResponseTruncatedMidResponse(t *testing.T) {
	block, _, _ := dualBlock()
	full := append(append(append([]byte{}, handshakeBase...), tunFlagDualStack), block...)

	// Cuts inside the 9-byte prefix and inside the advertised dual block are
	// both fatal; a cut at exactly 9 or 10 is not (the response is then a
	// legitimate legacy / flags-only one).
	for _, k := range []int{1, 4, 8, 11, 20, 41} {
		conn := chunkedConn(t, full[:k])
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		if _, n, err := readHandshakeResponse(conn, tunHandshakeVersionDualStack); err == nil {
			t.Errorf("truncated at %d bytes: got n=%d and no error, want an error", k, n)
		}
	}

	// The exit that hangs up before answering at all: a refused or reset
	// connection has to propagate, not come back as an empty response that the
	// caller then parses as a legacy one and treats as a successful connect.
	for _, version := range []byte{tunHandshakeVersion, tunHandshakeVersionDualStack} {
		conn := &scriptedConn{} // any read fails
		resp, n, err := readHandshakeResponse(conn, version)
		if err == nil {
			t.Errorf("version 0x%02x: silent server accepted, got n=%d", version, n)
		}
		if resp != nil || n != 0 {
			t.Errorf("version 0x%02x: error path returned resp=%v n=%d, want nil/0", version, resp, n)
		}
	}
}

// TestReadHandshakeResponseNoExtraReadOnV3Response pins that a complete
// response costs exactly one read, whatever version the client announced.
// scriptedConn errors on any read past its script, so a second read fails the
// test outright.
//
// A response that already carries its flags byte tells the reader everything
// it needs, so nothing further is fetched. The bare 9-byte form is a different
// case and is covered by the peek tests: there the reader cannot know whether
// a tenth byte is coming and pays a bounded grace period to find out.
func TestReadHandshakeResponseNoExtraReadOnV3Response(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		version byte
	}{
		{"v3 probe-only, v3 client",
			append(append([]byte{}, handshakeBase...), tunFlagMTUProbe), tunHandshakeVersion},
		{"v3 probe-only, v4 client",
			append(append([]byte{}, handshakeBase...), tunFlagMTUProbe), tunHandshakeVersionDualStack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{chunks: [][]byte{tc.payload}}
			_, n, err := readHandshakeResponse(conn, tc.version)
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if n != len(tc.payload) {
				t.Errorf("n = %d, want %d", n, len(tc.payload))
			}
			if conn.idx != 1 {
				t.Errorf("consumed %d reads, want exactly 1", conn.idx)
			}
		})
	}
}

// TestPeekHandshakeFlagsUnarmableDeadline covers the transport that cannot set
// a read deadline. The peek must then not read at all: an unbounded read of
// the tenth byte against a legacy exit blocks until the outer handshake
// timeout, turning a working IPv4-only connect into a ten-second hang.
func TestPeekHandshakeFlagsUnarmableDeadline(t *testing.T) {
	conn := &deadlineErrConn{
		scriptedConn: scriptedConn{chunks: [][]byte{{tunFlagDualStack}}},
	}
	resp := make([]byte, handshakeRespBufSize)
	copy(resp, handshakeBase)

	if got := peekHandshakeFlags(conn, resp, 9); got != 9 {
		t.Errorf("peekHandshakeFlags = %d, want 9 (no read without a deadline)", got)
	}
	if conn.reads != 0 {
		t.Errorf("peek issued %d reads, want 0", conn.reads)
	}
}

// TestPeekHandshakeFlagsRestoresDeadline checks the deadline handed back to the
// caller. The peek narrows the read deadline to its grace window; leaving it
// narrowed would make the reads that follow (the dual block, then the whole
// packet loop) time out after 300ms.
func TestPeekHandshakeFlagsRestoresDeadline(t *testing.T) {
	rec := &deadlineRecorderConn{
		scriptedConn: scriptedConn{chunks: [][]byte{{tunFlagDualStack}}},
	}
	resp := make([]byte, handshakeRespBufSize)
	copy(resp, handshakeBase)

	before := time.Now()
	if got := peekHandshakeFlags(rec, resp, 9); got != 10 {
		t.Fatalf("peekHandshakeFlags = %d, want 10", got)
	}
	if len(rec.deadlines) != 2 {
		t.Fatalf("armed %d deadlines, want 2 (grace, then restore)", len(rec.deadlines))
	}
	if d := rec.deadlines[0].Sub(before); d > handshakeFlagsGrace+time.Second {
		t.Errorf("grace deadline is %v out, want about %v", d, handshakeFlagsGrace)
	}
	if d := rec.deadlines[1].Sub(before); d < handshakeReadTimeout/2 {
		t.Errorf("restored deadline is %v out, want about %v", d, handshakeReadTimeout)
	}
}

// deadlineRecorderConn records every read deadline armed on it.
type deadlineRecorderConn struct {
	scriptedConn
	deadlines []time.Time
}

func (c *deadlineRecorderConn) SetReadDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}

// TestReadDualStackBlockBufferTooSmall covers the guard against an advertised
// block that does not fit the response buffer. Without it the io.ReadFull below
// would slice out of range and panic inside the connect path.
func TestReadDualStackBlockBufferTooSmall(t *testing.T) {
	// Base 10 + 32 = 42 needed, but the buffer holds 30.
	resp := make([]byte, 30)
	copy(resp, handshakeBase)
	resp[9] = tunFlagDualStack

	conn := &scriptedConn{} // must not be read: the size check comes first
	n, err := readResponseTail(conn, resp, 10, tunHandshakeVersionDualStack)
	if err == nil {
		t.Fatalf("undersized buffer accepted: n=%d", n)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %v, want it to name the oversized response", err)
	}
	if conn.idx != 0 {
		t.Errorf("issued %d reads before the size check, want 0", conn.idx)
	}
}

// TestReadDualStackBlockBaseReadFailure covers the port-hop base completion:
// with both flags set the block's offset depends on resp[19], so the base has
// to be finished first. A server that stops after the flags byte must produce
// an error naming that step, not a silent short read whose n then points the
// block parse at the wrong offset.
func TestReadDualStackBlockBaseReadFailure(t *testing.T) {
	resp := make([]byte, handshakeRespBufSize)
	copy(resp, handshakeBase)
	resp[9] = tunFlagPortHopping | tunFlagDualStack

	conn := &scriptedConn{} // read fails immediately
	if _, err := readResponseTail(conn, resp, 10, tunHandshakeVersionDualStack); err == nil {
		t.Fatal("expected an error when the port-hop base never completes")
	} else if !strings.Contains(err.Error(), "base read failed") {
		t.Errorf("error = %v, want it to name the base read", err)
	}
}

// TestHandshakeResponseBaseLenMalformed pins the sizing decisions for
// responses that do not fit any valid layout. The value feeds the offset the
// 32-byte v6 block is read from, so a wrong answer here reads the block from
// the wrong place and desyncs the stream.
func TestHandshakeResponseBaseLenMalformed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   byte
		seedLen byte
		n       int
		want    int
	}{
		// Error responses and legacy servers: no flags byte at all.
		{"below the flags byte", 0, 0, 5, 5},
		{"exactly the prefix", 0, 0, 9, 9},
		// Port hopping advertised but the response is too short to tell v1
		// from v2: fall back to what has actually been read.
		{"port-hop flag, 10 bytes", tunFlagPortHopping, 0, 10, 10},
		{"port-hop flag, 13 bytes", tunFlagPortHopping, 0, 13, 13},
		// A seed length past the 32-byte cap is nonsense, so the response is
		// read as the v1 form rather than trusted into an out-of-range offset.
		{"seed length over the cap", tunFlagPortHopping, 200, 60, 14},
		{"seed length at the cap", tunFlagPortHopping, 32, 60, 52},
		// No port hopping means the base is the flags-only form, whatever
		// trails it.
		{"probe only, long response", tunFlagMTUProbe, 200, 60, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := make([]byte, 96)
			copy(resp, handshakeBase)
			resp[9] = tc.flags
			resp[19] = tc.seedLen
			if got := handshakeResponseBaseLen(resp, tc.n); got != tc.want {
				t.Errorf("handshakeResponseBaseLen(n=%d) = %d, want %d", tc.n, got, tc.want)
			}
		})
	}
}
