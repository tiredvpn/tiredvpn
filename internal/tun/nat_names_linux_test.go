//go:build linux
// +build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
)

// nftNameMaxLen is the nftables limit on a table name (NFT_NAME_MAXLEN, 256,
// minus the NUL). A longer name is rejected by the kernel, so NAT never gets
// installed and the exit forwards nothing.
const nftNameMaxLen = 255

// TestSanitizeNftNameCharset pins the output charset. nftables accepts a
// limited set in a table name; a stray ':' or '/' from a CIDR makes the add
// fail, and SetupServerNAT only warns, so the exit comes up with no NAT at all.
func TestSanitizeNftNameCharset(t *testing.T) {
	for _, in := range []string{
		"10.8.0.0/24",
		"fd00:10:8::/64",
		"2001:db8:abcd:ef01::/64",
		"",
		"---",
		"a b\tc\n",
		"ПУЛ",       // non-ASCII: every rune maps out
		"pool%$#@!", // shell metacharacters
	} {
		got := sanitizeNftName(in)
		for _, r := range got {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
			if !ok {
				t.Errorf("sanitizeNftName(%q) = %q, contains %q", in, got, r)
			}
		}
	}
}

// TestSanitizeNftNameStable checks determinism. The table is looked up by name
// on teardown and replaced by name on restart, so the same pool has to produce
// the same name every time — an unstable name leaks a table per restart and
// each one keeps masquerading.
func TestSanitizeNftNameStable(t *testing.T) {
	for _, pool := range []string{"10.8.0.0/24", "fd00:10:8::/64", "192.168.1.0/24"} {
		first := sanitizeNftName(pool)
		for range 8 {
			if got := sanitizeNftName(pool); got != first {
				t.Fatalf("sanitizeNftName(%q) = %q then %q", pool, first, got)
			}
		}
		if got := natTableNameFor(pool); got != natTableNameFor(pool) {
			t.Errorf("natTableNameFor(%q) is not stable", pool)
		}
		if got := nat6TableNameFor(pool); got != nat6TableNameFor(pool) {
			t.Errorf("nat6TableNameFor(%q) is not stable", pool)
		}
	}
}

// TestSanitizeNftNameDoesNotGrow pins that sanitizing never lengthens its
// input. The length check below reasons about the CIDR's length, which only
// holds if one input byte can never become several.
func TestSanitizeNftNameDoesNotGrow(t *testing.T) {
	for _, in := range []string{
		"10.8.0.0/24",
		"fd00:10:8::/64",
		"ПУЛ",
		strings.Repeat("fd00:10:8::/64", 40),
	} {
		if got := sanitizeNftName(in); len(got) > len(in) {
			t.Errorf("sanitizeNftName(%q) grew from %d to %d bytes", in, len(in), len(got))
		}
	}
}

// TestNATTableNameLength keeps the generated names inside the kernel's limit
// for every pool that can actually reach these functions: the pool string is a
// canonical CIDR from ParseCIDR().String(), whose longest v6 form is well under
// the cap even with the prefix.
func TestNATTableNameLength(t *testing.T) {
	pools := []string{
		"10.8.0.0/24",
		"0.0.0.0/0",
		"255.255.255.255/32",
		"fd00:10:8::/64",
		"::/0",
		// The longest canonical IPv6 CIDR string: eight 4-digit groups plus a
		// 3-digit prefix length.
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	}
	for _, pool := range pools {
		for _, name := range []string{natTableNameFor(pool), nat6TableNameFor(pool)} {
			if len(name) > nftNameMaxLen {
				t.Errorf("table name for %q is %d bytes, over the %d limit: %q",
					pool, len(name), nftNameMaxLen, name)
			}
			if name == "" {
				t.Errorf("empty table name for pool %q", pool)
			}
		}
	}
}

// TestNATTableNamesNoCollisionAcrossPools is the multi-instance guarantee at
// scale. installNATRules replaces its table wholesale, so two pools sharing a
// name means one instance wipes the other's NAT on every start — the classic
// "the other tunnel stopped forwarding when I restarted this one". The single
// pair checked elsewhere would not catch a sanitizer that collapses digits or
// drops separators, so this sweeps a realistic address space.
func TestNATTableNamesNoCollisionAcrossPools(t *testing.T) {
	seen := make(map[string]string)
	add := func(name, pool string) {
		t.Helper()
		if prev, dup := seen[name]; dup && prev != pool {
			t.Fatalf("pools %q and %q share table name %q", prev, pool, name)
		}
		seen[name] = pool
	}

	for a := range 8 {
		for b := range 32 {
			v4 := fmt.Sprintf("10.%d.%d.0/24", a, b)
			add(natTableNameFor(v4), v4)

			v6 := fmt.Sprintf("fd00:%x:%x::/64", a, b)
			add(nat6TableNameFor(v6), v6)
		}
	}
	// Different prefix lengths on the same network must not collide either:
	// they are different pools and get separate tables.
	for _, mask := range []string{"/8", "/16", "/24", "/25", "/32"} {
		pool := "10.8.0.0" + mask
		add(natTableNameFor(pool), pool)
	}
}

// TestNATTableNamesSeparateFamilies pins that the v4 and v6 names never meet.
// A dual-stack exit installs both for the same tunnel; one name for both would
// have the ip6 table replace the ip one and drop all IPv4 NAT.
func TestNATTableNamesSeparateFamilies(t *testing.T) {
	for _, pool := range []string{"10.8.0.0/24", "fd00:10:8::/64", "", "x"} {
		v4, v6 := natTableNameFor(pool), nat6TableNameFor(pool)
		if v4 == v6 {
			t.Errorf("pool %q: v4 and v6 table names collide at %q", pool, v4)
		}
		if !strings.HasPrefix(v4, "tiredvpn-nat-") {
			t.Errorf("v4 name %q lost its prefix", v4)
		}
		if !strings.HasPrefix(v6, "tiredvpn-nat6-") {
			t.Errorf("v6 name %q lost its prefix", v6)
		}
		// The legacy flat table is deliberately left alone on half-upgraded
		// hosts, so no generated name may equal it.
		if v4 == "tiredvpn-nat" || v6 == "tiredvpn-nat" {
			t.Errorf("pool %q generates the legacy flat table name", pool)
		}
	}
}

// TestEnsureIPv6AcceptRAUnwritable covers the sysctl that cannot be written:
// a read-only /proc entry, a locked-down container, an LSM in the way. The
// function must warn and return, leaving the value alone — a panic or a retry
// loop here happens during NAT setup, before the exit ever serves a client.
func TestEnsureIPv6AcceptRAUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions, so an unwritable file cannot be simulated")
	}

	path := filepath.Join(t.TempDir(), "accept_ra")
	if err := os.WriteFile(path, []byte("1\n"), 0444); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ensureIPv6AcceptRAAt(path, "eth0")

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "1\n" {
		t.Errorf("accept_ra = %q, want it left at %q", got, "1\n")
	}
}

// TestEnsureIPv6AcceptRAUnreadable covers the entry that cannot even be read.
// The read failure has to be the end of it: the fallback of writing anyway
// would set accept_ra=2 on an interface whose policy is accept_ra=0, changing
// host network policy the VPN does not own.
func TestEnsureIPv6AcceptRAUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions, so an unreadable file cannot be simulated")
	}

	path := filepath.Join(t.TempDir(), "accept_ra")
	if err := os.WriteFile(path, []byte("1\n"), 0000); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ensureIPv6AcceptRAAt(path, "eth0")

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "1\n" {
		t.Errorf("accept_ra = %q, want it untouched at %q", got, "1\n")
	}
}

// TestEnsureIPv6AcceptRAValueParsing pins how the current value is read. /proc
// hands back a trailing newline and some setups leave stray whitespace, so a
// literal string compare against "0" or "2" would miss them and rewrite a
// sysctl that was already correct — or, worse, one that is 0 by policy.
func TestEnsureIPv6AcceptRAValueParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  string
		want string
	}{
		{"no trailing newline", "2", "2"},
		{"padded with spaces", "  0  ", "  0  "},
		{"padded with newlines", "\n2\n", "\n2\n"},
		{"one, no newline", "1", "2\n"},
		{"one, padded", " 1 \n", "2\n"},
		// Anything outside {0,1,2} is not a value the kernel produces. The
		// current behaviour is to normalise it to 2; pinned so a change is
		// deliberate rather than incidental.
		{"unexpected value", "3\n", "2\n"},
		{"empty file", "", "2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "accept_ra")
			if err := os.WriteFile(path, []byte(tc.cur), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ensureIPv6AcceptRAAt(path, "eth0")
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("accept_ra = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEnsureIPv6AcceptRAOnDirectory covers a path that exists but is not a
// file. Both the read and the write fail; the function must still just warn.
func TestEnsureIPv6AcceptRAOnDirectory(t *testing.T) {
	ensureIPv6AcceptRAAt(t.TempDir(), "eth0")
}

// TestWarnIfForeignForwardDropIsReadOnly exercises the foreign-chain probe. It
// runs during NAT setup on every exit start, so it has to survive a host where
// nftables is unavailable or unreadable (no CAP_NET_ADMIN, netns without the
// subsystem) by staying quiet rather than panicking or blocking startup.
//
// Without CAP_NET_ADMIN the chain listing fails and only the early-return path
// is exercised; the branch that actually finds a foreign drop policy needs a
// privileged host with such a chain installed and is not covered here.
func TestWarnIfForeignForwardDropIsReadOnly(t *testing.T) {
	before := nftTableNames(t)

	for _, family := range []nftables.TableFamily{
		nftables.TableFamilyIPv4,
		nftables.TableFamilyIPv6,
	} {
		warnIfForeignForwardDrop(family, "test")
	}

	// The probe reads; it must never add, drop or rename a table, least of all
	// one belonging to a firewall it does not own.
	if after := nftTableNames(t); !equalStringSets(before, after) {
		t.Errorf("nftables tables changed: %v -> %v", before, after)
	}
}

// nftTableNames lists the nftables tables visible to this process, or nil when
// nftables cannot be reached at all.
func nftTableNames(t *testing.T) map[string]bool {
	t.Helper()
	conn, err := nftables.New()
	if err != nil {
		return nil
	}
	tables, err := conn.ListTables()
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(tables))
	for _, tbl := range tables {
		out[fmt.Sprintf("%d/%s", tbl.Family, tbl.Name)] = true
	}
	return out
}

func equalStringSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// TestHostRouteExistsAbsentRoutes checks the negative answer for both families
// without needing root. Teardown deletes a bypass route only when it pinned it
// itself, so a false positive here strands the next client start by removing
// the operator's own route to the server.
//
// The addresses are from the documentation ranges, which nothing routes to.
func TestHostRouteExistsAbsentRoutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		dst  *net.IPNet
		v6   bool
	}{
		{"v6 /128", &net.IPNet{
			IP:   net.ParseIP("2001:db8:dead:beef::1"),
			Mask: net.CIDRMask(128, 128),
		}, true},
		{"v4 /32", &net.IPNet{
			IP:   net.ParseIP("192.0.2.1").To4(),
			Mask: net.CIDRMask(32, 32),
		}, false},
		{"v4 /32 in the second documentation range", &net.IPNet{
			IP:   net.ParseIP("198.51.100.7").To4(),
			Mask: net.CIDRMask(32, 32),
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repeated: the answer must not depend on netlink state left over
			// from the previous call.
			for i := range 3 {
				if hostRouteExists(tc.dst, tc.v6) {
					t.Fatalf("call %d: hostRouteExists(%s) = true, want false", i, tc.dst)
				}
			}
		})
	}
}

// TestHostRouteExistsFamilyIsHonoured pins that the family argument is used.
// Asking for a v4 destination in the v6 table (or the reverse) must not match:
// the caller decides the family from the bypass address, and a mismatch there
// would have teardown believe somebody else owns a route it pinned itself.
func TestHostRouteExistsFamilyIsHonoured(t *testing.T) {
	v4 := &net.IPNet{IP: net.ParseIP("192.0.2.1").To4(), Mask: net.CIDRMask(32, 32)}
	if hostRouteExists(v4, true) {
		t.Errorf("a v4 destination matched in the v6 table")
	}

	v6 := &net.IPNet{IP: net.ParseIP("2001:db8:dead:beef::1"), Mask: net.CIDRMask(128, 128)}
	if hostRouteExists(v6, false) {
		t.Errorf("a v6 destination matched in the v4 table")
	}
}
