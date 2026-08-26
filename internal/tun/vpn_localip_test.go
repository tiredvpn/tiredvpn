package tun

import (
	"net"
	"testing"
)

// TestLocalIPReportsAssignedNotRequested drives the real assignment path: the
// client asks for 10.8.0.2, the exit hands back 10.8.5.3, and LocalIP must
// report the assigned address. This is the fact the "VPN started on ... (IP:
// %s)" line needs; printing the configured address there once produced a report
// of two clients sharing one address that never happened.
//
// TUNDevice is a zero value on purpose: UpdateLocalIP fails fast on
// netlink.LinkByName("") without touching the host, and the caller tolerates
// that failure — so the test exercises the localIP bookkeeping without root.
func TestLocalIPReportsAssignedNotRequested(t *testing.T) {
	requested := net.IPv4(10, 8, 0, 2)
	assigned := net.IPv4(10, 8, 5, 3)

	// [status:1][serverIP:4][assignedClientIP:4][flags:1]
	resp := []byte{0x00, 10, 8, 0, 1, 10, 8, 5, 3, 0x00}
	conn := &scriptedConn{chunks: [][]byte{resp}}

	v := &VPNClient{tun: &TUNDevice{mtu: 1280}, localIP: requested}
	if err := v.performHandshake(conn); err != nil {
		t.Fatalf("performHandshake: %v", err)
	}

	got := v.LocalIP()
	if !got.Equal(assigned) {
		t.Errorf("LocalIP() = %s, want the assigned %s", got, assigned)
	}
	if got.Equal(requested) {
		t.Errorf("LocalIP() = %s, the requested address — this is the defect", got)
	}
}

// TestLocalIPKeepsRequestedWhenEchoed covers the other outcome: an exit that
// hands back the address that was asked for. LocalIP must still be the truth,
// which here happens to equal the request.
func TestLocalIPKeepsRequestedWhenEchoed(t *testing.T) {
	requested := net.IPv4(10, 8, 0, 2)
	resp := []byte{0x00, 10, 8, 0, 1, 10, 8, 0, 2, 0x00}
	conn := &scriptedConn{chunks: [][]byte{resp}}

	v := &VPNClient{tun: &TUNDevice{mtu: 1280}, localIP: requested}
	if err := v.performHandshake(conn); err != nil {
		t.Fatalf("performHandshake: %v", err)
	}
	if got := v.LocalIP(); !got.Equal(requested) {
		t.Errorf("LocalIP() = %s, want %s", got, requested)
	}
}

// TestLocalIPReturnsCopy: net.IP is a slice, so handing out the live one would
// let a caller rewrite the client's idea of its own address.
func TestLocalIPReturnsCopy(t *testing.T) {
	v := &VPNClient{localIP: net.IPv4(10, 8, 5, 3)}

	got := v.LocalIP()
	for i := range got {
		got[i] = 0xff
	}

	if after := v.LocalIP(); !after.Equal(net.IPv4(10, 8, 5, 3)) {
		t.Errorf("mutating the returned IP changed client state: %s", after)
	}
}

// TestLocalIPNilBeforeAssignment: a client that never handshook has no address,
// and must say so rather than panic.
func TestLocalIPNilBeforeAssignment(t *testing.T) {
	if got := (&VPNClient{}).LocalIP(); got != nil {
		t.Errorf("LocalIP() = %s on a fresh client, want nil", got)
	}
}
