package server

import (
	"net"
	"testing"
)

func TestAppendSplitTUNOriginRoundTrip(t *testing.T) {
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03} // [mode][ip:4][mtu:2][ver:1]

	cases := []string{"79.139.165.170", "2001:db8::1", "185.22.60.152"}
	for _, origin := range cases {
		t.Run(origin, func(t *testing.T) {
			got, gotOrigin := splitTUNOrigin(appendTUNOrigin(handshake, origin))
			if gotOrigin != origin {
				t.Errorf("origin = %q, want %q", gotOrigin, origin)
			}
			if string(got) != string(handshake) {
				t.Errorf("handshake = %x, want %x", got, handshake)
			}
		})
	}
}

func TestSplitTUNOriginWithoutExtension(t *testing.T) {
	// A payload from a client (or an older relay) has no trailer and must come
	// back byte-identical, otherwise the handshake parse shifts.
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03}
	got, origin := splitTUNOrigin(handshake)
	if origin != "" {
		t.Errorf("origin = %q, want empty", origin)
	}
	if string(got) != string(handshake) {
		t.Errorf("handshake = %x, want %x", got, handshake)
	}
}

func TestSplitTUNOriginIgnoresStrayMagic(t *testing.T) {
	// The magic can occur inside packet-ish payload bytes; without a well-formed
	// length trailer it must not be treated as an origin.
	payload := append([]byte{0x02, 10, 8, 0, 2}, tunOriginMagic...)
	payload = append(payload, 0xff, 0xff) // length claims 255 bytes, only 2 present
	got, origin := splitTUNOrigin(payload)
	if origin != "" {
		t.Errorf("origin = %q, want empty", origin)
	}
	if string(got) != string(payload) {
		t.Errorf("payload was modified: %x", got)
	}
}

func TestAppendTUNOriginEmpty(t *testing.T) {
	handshake := []byte{0x02, 10, 8, 0, 2, 0x05, 0x78, 0x03}
	if got := appendTUNOrigin(handshake, ""); string(got) != string(handshake) {
		t.Errorf("empty origin changed the payload: %x", got)
	}
}

func TestAllocationKey(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
		origin   string
		want     string
	}{
		// Two boxes on the global secret must not share a lease - this is the
		// flap that had usa2 handing 10.8.5.2 to both the laptop and the RU hop.
		{"global gets qualified", "global", "79.139.165.170", "global@79.139.165.170"},
		{"global other origin", "global", "185.22.60.152", "global@185.22.60.152"},
		// A named client keeps its identity so its IP survives an address change.
		{"named client untouched", "reality:4d5e13abbf0e8fd3", "79.139.165.170", "reality:4d5e13abbf0e8fd3"},
		{"global without origin", "global", "", "global"},
		{"empty client", "", "1.2.3.4", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allocationKey(c.clientID, c.origin); got != c.want {
				t.Errorf("allocationKey(%q, %q) = %q, want %q", c.clientID, c.origin, got, c.want)
			}
		})
	}
}

func TestOriginOf(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "79.139.165.170:2064")
	if err != nil {
		t.Fatal(err)
	}
	if got := originOf(addr); got != "79.139.165.170" {
		t.Errorf("originOf = %q, want the host without the port", got)
	}
	if got := originOf(nil); got != "" {
		t.Errorf("originOf(nil) = %q, want empty", got)
	}
}

func TestGlobalClientsGetDistinctIPs(t *testing.T) {
	pool, err := NewIPPool(IPPoolConfig{Network: "10.8.5.0/24", ServerIP: "10.8.5.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	laptop := allocationKey(globalClientID, "79.139.165.170")
	ruhop := allocationKey(globalClientID, "185.22.60.152")

	first, err := pool.Allocate(laptop, net.ParseIP("10.8.5.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Allocate(ruhop, net.ParseIP("10.8.5.2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Equal(second) {
		t.Fatalf("both global clients got %s; they must not share a tunnel IP", first)
	}

	// Same client reconnecting keeps its address (sticky lease).
	again, err := pool.Allocate(laptop, net.ParseIP("10.8.5.9"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(first) {
		t.Errorf("reconnect got %s, want the sticky %s", again, first)
	}
}
