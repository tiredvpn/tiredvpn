package control

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// mustSerialize serializes m and fails the test on error. All existing frames
// use tiny payloads, so an error here is a bug in the test's assumptions, not
// an expected outcome.
func mustSerialize(t *testing.T, m *Message) []byte {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatalf("Serialize(%d-byte payload) unexpected error: %v", len(m.Payload), err)
	}
	return wire
}

func TestSerializeWireFormat(t *testing.T) {
	m := &Message{Type: MsgStatsResp, Seq: 0x2a, Payload: []byte("hi")}
	got := mustSerialize(t, m)
	want := []byte{
		ControlMagic, // 0xCC
		MsgStatsResp, // type
		0x2a,         // seq
		0x00, 0x02,   // length = 2, big-endian
		'h', 'i',
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Serialize() = % x, want % x", got, want)
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	for _, c := range []struct {
		name string
		msg  Message
	}{
		{"empty payload", Message{Type: MsgPing, Seq: 1}},
		{"pong no payload", Message{Type: MsgPong, Seq: 255}},
		{"with payload", Message{Type: MsgStatsResp, Seq: 7, Payload: []byte("stats-data")}},
		{"seq zero", Message{Type: MsgStatsReq, Seq: 0, Payload: []byte{0x00, 0xff}}},
	} {
		wire := mustSerialize(t, &c.msg)
		parsed := ParseMessage(wire)
		if parsed == nil {
			t.Fatalf("%s: ParseMessage returned nil for valid frame", c.name)
		}
		if parsed.Type != c.msg.Type || parsed.Seq != c.msg.Seq {
			t.Errorf("%s: header mismatch: got type=0x%02x seq=%d, want type=0x%02x seq=%d",
				c.name, parsed.Type, parsed.Seq, c.msg.Type, c.msg.Seq)
		}
		// bytes.Equal treats nil and empty slices as equal, covering the
		// no-payload messages.
		if !bytes.Equal(parsed.Payload, c.msg.Payload) {
			t.Errorf("%s: payload mismatch: got % x, want % x", c.name, parsed.Payload, c.msg.Payload)
		}
	}
}

func TestParseMessageRejects(t *testing.T) {
	valid := mustSerialize(t, &Message{Type: MsgStatsResp, Seq: 1, Payload: []byte("abcde")})

	for _, c := range []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"shorter than header", []byte{ControlMagic, MsgPing, 0x01, 0x00}}, // 4 bytes
		{"wrong magic", []byte{0xAB, MsgPing, 0x01, 0x00, 0x00}},
		{"truncated payload", valid[:len(valid)-2]}, // length says 5, only 3 present
	} {
		if got := ParseMessage(c.data); got != nil {
			t.Errorf("%s: ParseMessage = %+v, want nil", c.name, got)
		}
	}

	// Positive control: the untruncated frame parses.
	if ParseMessage(valid) == nil {
		t.Fatal("positive control: valid frame parsed as nil")
	}
}

func TestParseMessageIgnoresTrailingBytes(t *testing.T) {
	wire := mustSerialize(t, &Message{Type: MsgPong, Seq: 3, Payload: []byte("xy")})
	framed := append(append([]byte{}, wire...), 0xDE, 0xAD)
	m := ParseMessage(framed)
	if m == nil {
		t.Fatal("ParseMessage returned nil for frame with trailing bytes")
	}
	if !bytes.Equal(m.Payload, []byte("xy")) {
		t.Errorf("payload = % x, want 'xy' (trailing bytes must not leak in)", m.Payload)
	}
}

func TestIsControlMessage(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
		want bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"magic", []byte{ControlMagic, 0x01}, true},
		{"magic only", []byte{ControlMagic}, true},
		{"other", []byte{0x00}, false},
	} {
		if got := IsControlMessage(c.data); got != c.want {
			t.Errorf("%s: IsControlMessage = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestHandleServerMessagePingPong: a PING must produce a PONG with the same
// seq, and the handler must report it consumed the message.
func TestHandleServerMessagePingPong(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	ping := mustSerialize(t, &Message{Type: MsgPing, Seq: 0x11})

	handled := make(chan bool, 1)
	go func() {
		handled <- HandleServerMessage(srv, ping)
	}()

	_ = cli.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("reading PONG: %v", err)
	}
	pong := ParseMessage(buf[:n])
	if pong == nil {
		t.Fatalf("server reply is not a control message: % x", buf[:n])
	}
	if pong.Type != MsgPong {
		t.Errorf("reply type = 0x%02x, want MsgPong (0x%02x)", pong.Type, MsgPong)
	}
	if pong.Seq != 0x11 {
		t.Errorf("reply seq = %d, want 0x11", pong.Seq)
	}
	if !<-handled {
		t.Error("HandleServerMessage returned false for a valid PING")
	}
}

func TestHandleServerMessageNonControl(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	if HandleServerMessage(srv, []byte{0x00, 0x01, 0x02}) {
		t.Error("HandleServerMessage returned true for non-control data")
	}
}

// TestHandleServerMessageNoReply: StatsReq and unknown types are consumed
// (return true) but must NOT write anything back. Verified against the PONG
// positive control above (same harness) by asserting the peer read times out.
func TestHandleServerMessageNoReply(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  byte
	}{
		{"stats req", MsgStatsReq},
		{"unknown type", 0x7F},
	} {
		srv, cli := net.Pipe()
		msg := mustSerialize(t, &Message{Type: c.typ, Seq: 5})

		handled := make(chan bool, 1)
		go func() {
			handled <- HandleServerMessage(srv, msg)
		}()

		_ = cli.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		buf := make([]byte, 16)
		n, err := cli.Read(buf)
		if err == nil {
			t.Errorf("%s: peer received %d bytes, expected no reply", c.name, n)
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Errorf("%s: expected read timeout, got %v", c.name, err)
		}
		if !<-handled {
			t.Errorf("%s: HandleServerMessage returned false", c.name)
		}
		_ = srv.Close()
		_ = cli.Close()
	}
}

// TestSerializeLengthField documents that the length header is the payload
// length encoded big-endian, matching MinMessageSize accounting.
func TestSerializeLengthField(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 300)
	wire := mustSerialize(t, &Message{Type: MsgStatsResp, Seq: 0, Payload: payload})
	if len(wire) != MinMessageSize+len(payload) {
		t.Fatalf("wire len = %d, want %d", len(wire), MinMessageSize+len(payload))
	}
	gotLen := binary.BigEndian.Uint16(wire[3:5])
	if int(gotLen) != len(payload) {
		t.Errorf("length field = %d, want %d", gotLen, len(payload))
	}
	if ParseMessage(wire) == nil {
		t.Error("300-byte-payload frame failed to round-trip through ParseMessage")
	}
}

// TestSerializeRejectsOversizedPayload is the guard against silent truncation.
// A payload past the uint16 ceiling cannot be length-encoded on the wire.
//
// On the old code Serialize took uint16(len(payload)): 70000 & 0xFFFF = 4464,
// so it returned a frame whose header claimed 4464 bytes. ParseMessage then
// read a truncated, wrong-length message with no error anywhere. Presented to
// that logic (length check removed), this test is red because err is nil.
func TestSerializeRejectsOversizedPayload(t *testing.T) {
	oversized := bytes.Repeat([]byte{0xAB}, MaxPayloadSize+1)
	wire, err := (&Message{Type: MsgStatsResp, Seq: 1, Payload: oversized}).Serialize()
	if err == nil {
		t.Fatalf("Serialize accepted %d-byte payload (max %d), want error", len(oversized), MaxPayloadSize)
	}
	if wire != nil {
		t.Errorf("Serialize returned %d bytes alongside the error, want nil", len(wire))
	}
}

// TestSerializeAcceptsMaxPayload is the positive control for the guard: the
// largest encodable payload must still serialize and round-trip cleanly, so
// the rejection above is proven to be a ceiling and not an off-by-one that
// bites legitimate frames.
func TestSerializeAcceptsMaxPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, MaxPayloadSize)
	wire := mustSerialize(t, &Message{Type: MsgStatsResp, Seq: 9, Payload: payload})
	parsed := ParseMessage(wire)
	if parsed == nil {
		t.Fatalf("max-payload frame (%d bytes) failed to parse", MaxPayloadSize)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Errorf("max-payload round-trip corrupted the payload (len got %d, want %d)",
			len(parsed.Payload), len(payload))
	}
}
