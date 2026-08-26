package tun

import (
	"net"
	"testing"
)

func ipStrings(list []net.IP) []string {
	out := make([]string, 0, len(list))
	for _, ip := range list {
		out = append(out, ip.String())
	}
	return out
}

func ipSet(list []net.IP) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, ip := range list {
		out[ip.String()] = true
	}
	return out
}

// TestServerAddrListOrdersAndDedupes: the two legacy fields lead so a
// single-server client keeps the exact ordering it had before the list existed,
// and an address repeated between -server and [[servers]] must not produce two
// entries (and, downstream, two identical host routes).
func TestServerAddrListOrdersAndDedupes(t *testing.T) {
	cases := []struct {
		name string
		cfg  VPNConfig
		want []string
	}{
		{"nothing", VPNConfig{}, nil},
		{"legacy only", VPNConfig{ServerAddr: "1.2.3.4:995"}, []string{"1.2.3.4:995"}},
		{"legacy pair, v6 first", VPNConfig{
			ServerAddr:   "1.2.3.4:995",
			ServerAddrV6: "[2001:db8::1]:995",
		}, []string{"[2001:db8::1]:995", "1.2.3.4:995"}},
		{"list appended after the legacy pair", VPNConfig{
			ServerAddr:  "1.2.3.4:995",
			ServerAddrs: []string{"5.6.7.8:995", "[2001:db8::9]:995"},
		}, []string{"1.2.3.4:995", "5.6.7.8:995", "[2001:db8::9]:995"}},
		{"list repeating the legacy address", VPNConfig{
			ServerAddr:  "1.2.3.4:995",
			ServerAddrs: []string{"1.2.3.4:995", "5.6.7.8:995"},
		}, []string{"1.2.3.4:995", "5.6.7.8:995"}},
		{"empty strings dropped", VPNConfig{
			ServerAddrs: []string{"", "5.6.7.8:995", ""},
		}, []string{"5.6.7.8:995"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := serverAddrList(c.cfg)
			if len(got) != len(c.want) {
				t.Fatalf("serverAddrList = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("serverAddrList = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestServerBypassIPsCoversEveryEndpoint is the whole point of phase 3 on
// Linux: with a full tunnel up, a dial to an endpoint that has no pinned host
// route goes into the tunnel and dies there. Pinning happens at startup for
// every endpoint, so this set has to be complete before the first switch.
func TestServerBypassIPsCoversEveryEndpoint(t *testing.T) {
	cfg := VPNConfig{
		ServerAddr:   "1.2.3.4:995",
		ServerAddrV6: "[2001:db8::1]:995",
		ServerAddrs: []string{
			"1.2.3.4:995", // duplicate of the legacy field
			"5.6.7.8:443",
			"[2001:db8::9]:995",
		},
	}
	got := ipSet(serverBypassIPs(cfg))
	for _, want := range []string{"1.2.3.4", "2001:db8::1", "5.6.7.8", "2001:db8::9"} {
		if !got[want] {
			t.Errorf("no bypass address for %s (got %v)", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("got %d bypass addresses, want 4 distinct ones: %v", len(got), got)
	}
}

// TestServerBypassIPsSingleServerUnchanged: a client with nothing but -server
// must produce exactly the one address it always did. This is the legacy path
// that every existing unit file takes.
func TestServerBypassIPsSingleServerUnchanged(t *testing.T) {
	got := serverBypassIPs(VPNConfig{ServerAddr: "31.44.3.165:995"})
	if len(got) != 1 || got[0].String() != "31.44.3.165" {
		t.Fatalf("serverBypassIPs = %v, want exactly [31.44.3.165]", ipStrings(got))
	}
}

func TestResolveBypassIPsLiterals(t *testing.T) {
	cases := []struct {
		addr string
		want string // empty = expect nothing
	}{
		{"31.44.3.165:995", "31.44.3.165"},
		{"31.44.3.165", "31.44.3.165"},
		{"[2001:db8::1]:995", "2001:db8::1"},
		{"", ""},
		{"not a host", ""},
	}
	for _, c := range cases {
		got := resolveBypassIPs(c.addr)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("resolveBypassIPs(%q) = %v, want nothing", c.addr, ipStrings(got))
			}
			continue
		}
		if len(got) != 1 || got[0].String() != c.want {
			t.Errorf("resolveBypassIPs(%q) = %v, want [%s]", c.addr, ipStrings(got), c.want)
		}
	}
}

// TestServerIP6sSpanTheWholeList: the IPv6 leak block has to punch a hole for
// every endpoint's v6 address, not just the pinned one - the client switches
// between them across reconnects, and a hole for an address it never dials
// costs nothing while a missing one costs the tunnel.
func TestServerIP6sSpanTheWholeList(t *testing.T) {
	cfg := VPNConfig{
		ServerAddr:  "1.2.3.4:995",
		ServerAddrs: []string{"[2001:db8::9]:995", "5.6.7.8:995", "[2001:db8::a]:443"},
	}
	got := ipSet(serverIP6s(cfg))
	for _, want := range []string{"2001:db8::9", "2001:db8::a"} {
		if !got[want] {
			t.Errorf("no leak-block hole for %s (got %v)", want, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d v6 addresses, want 2: %v", len(got), got)
	}
}
