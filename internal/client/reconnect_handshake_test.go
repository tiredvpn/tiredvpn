package client

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestSendReconnectHandshake pins the reconnect handshake wire format: the
// version byte follows the dual-stack knob (v0x04 only when -tun-ipv6 dual is
// active), and the dual path drains the trailing v6 address block so the
// relay that follows stays frame-aligned even when the response arrives in
// fragments.
func TestSendReconnectHandshake(t *testing.T) {
	server6 := net.ParseIP("fd00:10:8::1").To16()
	client6 := net.ParseIP("fd00:10:8::a08:2").To16()

	// scriptServer plays the exit side over a net.Pipe: it reads the 8-byte
	// handshake, reports the version byte, and writes the response chunks in
	// order (each chunk a separate Write, so fragmentation is exercised).
	scriptServer := func(t *testing.T, conn net.Conn, chunks ...[]byte) byte {
		t.Helper()
		hs := make([]byte, 8)
		if _, err := io.ReadFull(conn, hs); err != nil {
			t.Errorf("server read handshake: %v", err)
			return 0
		}
		if hs[0] != 0x02 {
			t.Errorf("handshake mode = 0x%02x, want 0x02 (TUN)", hs[0])
		}
		for _, c := range chunks {
			if _, err := conn.Write(c); err != nil {
				t.Errorf("server write response: %v", err)
				return hs[7]
			}
		}
		return hs[7]
	}

	baseResp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2} // status, serverIP, clientIP
	dualBlock := append(append([]byte{}, server6...), client6...)
	flagsResp := append(append([]byte{}, baseResp...), 0x04) // dual-stack cap flag

	t.Run("dual off sends v3 and parses v4-only response", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()

		verCh := make(chan byte, 1)
		go func() { verCh <- scriptServer(t, srv, baseResp) }()

		serverIP, assignedIP, serverIP6, assignedIP6, err := sendReconnectHandshake(cli, net.IPv4(10, 8, 0, 2), 1280, false)
		if err != nil {
			t.Fatalf("sendReconnectHandshake: %v", err)
		}
		if v := <-verCh; v != 0x03 {
			t.Errorf("version byte = 0x%02x, want 0x03", v)
		}
		if !serverIP.Equal(net.IPv4(10, 8, 0, 1)) || !assignedIP.Equal(net.IPv4(10, 8, 0, 2)) {
			t.Errorf("addrs = %s/%s, want 10.8.0.1/10.8.0.2", serverIP, assignedIP)
		}
		if serverIP6 != nil || assignedIP6 != nil {
			t.Errorf("v4-only reconnect must report no v6, got %s/%s", serverIP6, assignedIP6)
		}
	})

	t.Run("dual on sends v4 and drains the v6 block across fragments", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()

		verCh := make(chan byte, 1)
		go func() { verCh <- scriptServer(t, srv, flagsResp, dualBlock[:16], dualBlock[16:]) }()

		serverIP, assignedIP, serverIP6, assignedIP6, err := sendReconnectHandshake(cli, net.IPv4(10, 8, 0, 2), 1280, true)
		if err != nil {
			t.Fatalf("sendReconnectHandshake: %v", err)
		}
		if v := <-verCh; v != 0x04 {
			t.Errorf("version byte = 0x%02x, want 0x04", v)
		}
		if !serverIP.Equal(net.IPv4(10, 8, 0, 1)) || !assignedIP.Equal(net.IPv4(10, 8, 0, 2)) {
			t.Errorf("addrs = %s/%s, want 10.8.0.1/10.8.0.2", serverIP, assignedIP)
		}
		// The renegotiated v6 pair has to reach the caller: a host-owned
		// interface cannot recompute it, and the exit derives the client v6
		// from the (possibly new) v4 lease.
		if !serverIP6.Equal(net.IP(server6)) || !assignedIP6.Equal(net.IP(client6)) {
			t.Errorf("v6 pair = %s/%s, want %s/%s", serverIP6, assignedIP6, net.IP(server6), net.IP(client6))
		}
		// The dual path must have consumed the whole response; nothing may be
		// left for the relay to misparse. A write immediately after the
		// handshake must not race a leftover-read of the v6 block.
		if err := cli.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, err := cli.Read(make([]byte, 1)); err == nil {
			t.Errorf("expected no leftover bytes after handshake, got a read")
		}
	})

	t.Run("dual on, old server responds plain v3 layout", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()

		verCh := make(chan byte, 1)
		go func() { verCh <- scriptServer(t, srv, baseResp) }()

		_, assignedIP, serverIP6, assignedIP6, err := sendReconnectHandshake(cli, net.IPv4(10, 8, 0, 2), 1280, true)
		if err != nil {
			t.Fatalf("sendReconnectHandshake: %v", err)
		}
		if v := <-verCh; v != 0x04 {
			t.Errorf("version byte = 0x%02x, want 0x04 (client still asks)", v)
		}
		if !assignedIP.Equal(net.IPv4(10, 8, 0, 2)) {
			t.Errorf("assigned = %s, want 10.8.0.2", assignedIP)
		}
		if serverIP6 != nil || assignedIP6 != nil {
			t.Errorf("declined dual-stack must report no v6, got %s/%s", serverIP6, assignedIP6)
		}
	})

	t.Run("server rejection surfaces an error", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()

		go func() { scriptServer(t, srv, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}) }()

		if _, _, _, _, err := sendReconnectHandshake(cli, net.IPv4(10, 8, 0, 2), 1280, false); err == nil {
			t.Fatal("expected error on status=0x01, got nil")
		}
	})

	// A dual-stack response split at exactly the 9-byte legacy boundary used
	// to end the read there: the flags byte was never seen, the v6 block was
	// left in the stream and the relay that follows parsed it as [len][pkt].
	t.Run("dual on, response split at the 9-byte boundary", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()

		full := append(append([]byte{}, flagsResp...), dualBlock...)
		go func() {
			hs := make([]byte, 8)
			if _, err := io.ReadFull(srv, hs); err != nil {
				return
			}
			// One byte at a time: the worst case a TCP/TLS/stego transport can
			// hand the reader.
			for i := range full {
				if _, err := srv.Write(full[i : i+1]); err != nil {
					return
				}
			}
		}()

		_, assignedIP, serverIP6, assignedIP6, err := sendReconnectHandshake(cli, net.IPv4(10, 8, 0, 2), 1280, true)
		if err != nil {
			t.Fatalf("sendReconnectHandshake: %v", err)
		}
		if !assignedIP.Equal(net.IPv4(10, 8, 0, 2)) {
			t.Errorf("assigned = %s, want 10.8.0.2", assignedIP)
		}
		if !serverIP6.Equal(net.IP(server6)) || !assignedIP6.Equal(net.IP(client6)) {
			t.Errorf("v6 pair = %s/%s, want %s/%s", serverIP6, assignedIP6, net.IP(server6), net.IP(client6))
		}
		if err := cli.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, err := cli.Read(make([]byte, 1)); err == nil {
			t.Errorf("expected no leftover bytes after handshake, got a read")
		}
	})
}

// TestControlSocketIPv6PolicyMapping pins the mapping the control-socket mode
// applies: only an explicit "dual" opts into the dual-stack handshake; unset
// and "off" keep the historical v0x03 path. parseClientArgs coverage lives on
// the android build (cmd/tiredvpn/jni_android.go), so this exercises the
// shared policy parser the same way runControlSocketMode does.
func TestControlSocketIPv6PolicyMapping(t *testing.T) {
	for _, tc := range []struct {
		flagValue string
		wantDual  bool
		wantErr   bool
	}{
		{"", false, false},    // flag never set: default off
		{"off", false, false}, // explicit off
		{"dual", true, false},
		{"block", false, true}, // reserved, rejected by the parser
	} {
		dual, err := parseTunIPv6Policy(tc.flagValue)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTunIPv6Policy(%q) = %v, want error", tc.flagValue, dual)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTunIPv6Policy(%q) error: %v", tc.flagValue, err)
			continue
		}
		if dual != tc.wantDual {
			t.Errorf("parseTunIPv6Policy(%q) = %v, want dual=%v", tc.flagValue, dual, tc.wantDual)
		}
	}
}
