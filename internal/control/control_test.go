package control

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSerializeWireFormat(t *testing.T) {
	m := &Message{Type: MsgStatsResp, Seq: 0x2a, Payload: []byte("hi")}
	got := m.Serialize()
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
		wire := (&c.msg).Serialize()
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
	valid := (&Message{Type: MsgStatsResp, Seq: 1, Payload: []byte("abcde")}).Serialize()

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
	wire := (&Message{Type: MsgPong, Seq: 3, Payload: []byte("xy")}).Serialize()
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

	ping := (&Message{Type: MsgPing, Seq: 0x11}).Serialize()

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
		msg := (&Message{Type: c.typ, Seq: 5}).Serialize()

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
	wire := (&Message{Type: MsgStatsResp, Seq: 0, Payload: payload}).Serialize()
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
