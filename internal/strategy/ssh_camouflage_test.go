package strategy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestSSHPacketRoundTrip verifies WriteSSHPacket/ReadSSHPacket are inverses and
// that the framing obeys the SSH binary packet padding rules.
func TestSSHPacketRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},
		[]byte("a"),
		[]byte("hello world"),
		bytes.Repeat([]byte{0xAB}, 7), // exercise the (5+len)%8 boundary
		bytes.Repeat([]byte{0xCD}, 8),
		bytes.Repeat([]byte{0xEF}, 1024),
	}

	for i, p := range payloads {
		var buf bytes.Buffer
		if err := WriteSSHPacket(&buf, p); err != nil {
			t.Fatalf("payload %d: WriteSSHPacket: %v", i, err)
		}

		raw := buf.Bytes()

		// packet_length must cover padding_length byte + payload + padding.
		packetLen := binary.BigEndian.Uint32(raw[0:4])
		if int(packetLen) != len(raw)-4 {
			t.Fatalf("payload %d: packet_length=%d but body=%d", i, packetLen, len(raw)-4)
		}
		// The whole record (4-byte length + body) must be a multiple of 8.
		if len(raw)%sshBlockSize != 0 {
			t.Fatalf("payload %d: record length %d not multiple of %d", i, len(raw), sshBlockSize)
		}
		// padding_length must be at least 4.
		if int(raw[4]) < 4 {
			t.Fatalf("payload %d: padding_length=%d < 4", i, raw[4])
		}

		got, err := ReadSSHPacket(&buf)
		if err != nil {
			t.Fatalf("payload %d: ReadSSHPacket: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("payload %d: round trip mismatch: got %x want %x", i, got, p)
		}
	}
}

// TestSSHPacketReadInvalid checks that malformed packets are rejected.
func TestSSHPacketReadInvalid(t *testing.T) {
	// packet_length larger than the cap.
	var buf bytes.Buffer
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, sshMaxPacket+1)
	buf.Write(hdr)
	if _, err := ReadSSHPacket(&buf); err == nil {
		t.Fatal("expected error for oversized packet_length")
	}

	// padding_length larger than packet_length.
	buf.Reset()
	binary.BigEndian.PutUint32(hdr, 2)
	buf.Write(hdr)
	buf.Write([]byte{0xFF, 0x00}) // padding_length=255, one byte body
	if _, err := ReadSSHPacket(&buf); err == nil {
		t.Fatal("expected error for invalid padding_length")
	}
}

// TestSSHConnRoundTrip verifies the tunnel-phase connection frames and deframes a
// clean byte stream across an arbitrary split (large payload, small read buffer).
func TestSSHConnRoundTrip(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	a := NewSSHCamouflageConn(cli)
	b := NewSSHCamouflageConn(srv)

	msg := bytes.Repeat([]byte("TiredVPN-payload-"), 500) // > 8KB

	go func() {
		if _, err := a.Write(msg); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	got := make([]byte, 0, len(msg))
	tmp := make([]byte, 100) // deliberately small to force buffering
	for len(got) < len(msg) {
		n, err := b.Read(tmp)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, tmp[:n]...)
	}

	if !bytes.Equal(got, msg) {
		t.Fatalf("conn round trip mismatch (got %d bytes, want %d)", len(got), len(msg))
	}
}

// TestSSHConnIgnoresNonTunnelPackets ensures Read skips packets whose message
// type is not the tunnel-data type (e.g. an SSH ignore/keepalive message).
func TestSSHConnIgnoresNonTunnelPackets(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		// A non-tunnel SSH packet (message type 2 = SSH_MSG_IGNORE) ...
		_ = WriteSSHPacket(cli, []byte{0x02, 0x00, 0x00, 0x00, 0x00})
		// ... followed by a real tunnel-data packet.
		conn := NewSSHCamouflageConn(cli)
		_, _ = conn.Write([]byte("real"))
	}()

	b := NewSSHCamouflageConn(srv)
	buf := make([]byte, 16)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "real" {
		t.Fatalf("expected 'real', got %q", string(buf[:n]))
	}
}

// TestSSHAuthTokenVerify checks token generation and verification, including the
// ±1 time-bucket tolerance and rejection of wrong secrets / lengths.
func TestSSHAuthTokenVerify(t *testing.T) {
	secret := []byte("super-secret-key")

	token := GenerateSSHAuthToken(secret)
	if len(token) != sshAuthLen {
		t.Fatalf("token length = %d, want %d", len(token), sshAuthLen)
	}
	if !VerifySSHAuthToken(token, secret) {
		t.Fatal("current-bucket token failed to verify")
	}

	// Wrong secret must fail.
	if VerifySSHAuthToken(token, []byte("other-secret")) {
		t.Fatal("token verified against wrong secret")
	}

	// Wrong length must fail.
	if VerifySSHAuthToken(token[:16], secret) {
		t.Fatal("truncated token verified")
	}

	// Adjacent buckets must verify (clock skew tolerance).
	now := time.Now().Unix()
	for _, off := range []int64{-1, 1} {
		bucket := uint64((now / sshAuthBucket) + off)
		adj := sshAuthTokenForBucket(secret, bucket)
		if !VerifySSHAuthToken(adj, secret) {
			t.Fatalf("adjacent bucket (offset %d) failed to verify", off)
		}
	}

	// A bucket two steps away must fail.
	farBucket := uint64((now / sshAuthBucket) + 2)
	far := sshAuthTokenForBucket(secret, farBucket)
	if VerifySSHAuthToken(far, secret) {
		t.Fatal("far bucket (+2) unexpectedly verified")
	}
}

// TestSSHKexECDHParse verifies the ECDH pubkey builder/parser round trip and
// message-type checking.
func TestSSHKexECDHParse(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, sshAuthLen)

	payload := BuildSSHKexECDH(sshMsgKexECDHInit, key)
	got, err := ParseSSHKexPubKey(payload, sshMsgKexECDHInit)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("pubkey mismatch: got %x want %x", got, key)
	}

	// Wrong expected message type must fail.
	if _, err := ParseSSHKexPubKey(payload, sshMsgKexECDHReply); err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// TestSSHClientServerHandshake runs the real client handshake against a minimal
// server handshake to confirm both halves interoperate end to end.
func TestSSHClientServerHandshake(t *testing.T) {
	secret := []byte("handshake-secret")
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	clientErr := make(chan error, 1)
	go func() {
		clientErr <- performSSHClientHandshake(cli, secret)
	}()

	if err := fakeSSHServerHandshake(srv, secret); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
}

// fakeSSHServerHandshake mirrors the server-side handshake using only exported
// strategy helpers, so the test stays inside the strategy package.
func fakeSSHServerHandshake(conn net.Conn, secret []byte) error {
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil { // client banner
		return err
	}
	if _, err := conn.Write([]byte(SSHBanner)); err != nil {
		return err
	}
	if _, err := ReadSSHPacket(br); err != nil { // client KEXINIT
		return err
	}
	if err := WriteSSHPacket(conn, BuildSSHKexInit()); err != nil {
		return err
	}
	payload, err := ReadSSHPacket(br) // client ECDH init
	if err != nil {
		return err
	}
	token, err := ParseSSHKexPubKey(payload, sshMsgKexECDHInit)
	if err != nil {
		return err
	}
	if !VerifySSHAuthToken(token, secret) {
		return io.ErrUnexpectedEOF
	}
	return WriteSSHPacket(conn, BuildSSHKexECDH(sshMsgKexECDHReply, GenerateSSHAuthToken(secret)))
}
