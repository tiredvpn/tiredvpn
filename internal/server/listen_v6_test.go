package server

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestDeriveListenAddrV6 pins the address the IPv6 listener binds when the
// operator did not spell -listen-v6 out. The port must follow -listen; the old
// hardcoded "[::]:995" default is exactly the defect being fixed.
func TestDeriveListenAddrV6(t *testing.T) {
	cases := []struct {
		name     string
		listen   string
		want     string
		wantErr  string // substring the reason must mention; "" = must succeed
	}{
		{name: "port only", listen: ":443", want: "[::]:443"},
		{name: "v4 wildcard", listen: "0.0.0.0:443", want: "[::]:443"},
		// A concrete v4 address has no v6 counterpart, so the v6 socket widens
		// to the wildcard rather than not existing at all.
		{name: "concrete v4", listen: "1.2.3.4:443", want: "[::]:443"},
		{name: "hostname", listen: "vpn.example.com:995", want: "[::]:995"},
		{name: "non-995 port is not 995", listen: ":994", want: "[::]:994"},
		{name: "v4-mapped v6 counts as v4", listen: "[::ffff:1.2.3.4]:443", want: "[::]:443"},

		// -listen already names the v6 side; adding a second v6 socket would be
		// second-guessing the operator.
		{name: "v6 wildcard", listen: "[::]:443", wantErr: "already an IPv6 address"},
		{name: "v6 literal", listen: "[2001:db8::1]:443", wantErr: "already an IPv6 address"},

		// Malformed input must disable v6 with a reason, never panic or abort.
		{name: "no port", listen: "1.2.3.4", wantErr: "cannot parse"},
		{name: "empty port", listen: "1.2.3.4:", wantErr: "no port"},
		{name: "bare colon", listen: ":", wantErr: "no port"},
		{name: "empty", listen: "", wantErr: "nothing to derive"},
		{name: "too many colons", listen: "1:2:3", wantErr: "cannot parse"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveListenAddrV6(tc.listen)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("deriveListenAddrV6(%q) = %q, want error mentioning %q", tc.listen, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("reason = %q, want it to mention %q", err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("address = %q on error, want empty so the caller cannot bind it", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("deriveListenAddrV6(%q): %v", tc.listen, err)
			}
			if got != tc.want {
				t.Errorf("deriveListenAddrV6(%q) = %q, want %q", tc.listen, got, tc.want)
			}
		})
	}
}

// TestResolveListenAddrV6 covers the flag interaction: an explicit -listen-v6
// wins untouched (no behavior change for deployments that set it), an empty one
// is derived, and the caller can tell the two apart for the log line.
func TestResolveListenAddrV6(t *testing.T) {
	t.Run("explicit wins", func(t *testing.T) {
		cfg := &Config{ListenAddr: ":443", ListenAddrV6: "[::1]:9995"}
		addr, derived, err := resolveListenAddrV6(cfg)
		if err != nil {
			t.Fatalf("resolveListenAddrV6: %v", err)
		}
		if addr != "[::1]:9995" {
			t.Errorf("addr = %q, want the explicit [::1]:9995", addr)
		}
		if derived {
			t.Error("derived = true for an explicitly configured address")
		}
	})

	t.Run("explicit wins even over an unparsable -listen", func(t *testing.T) {
		cfg := &Config{ListenAddr: "garbage", ListenAddrV6: "[::]:9995"}
		addr, derived, err := resolveListenAddrV6(cfg)
		if err != nil || addr != "[::]:9995" || derived {
			t.Errorf("got (%q, %v, %v), want (\"[::]:9995\", false, nil)", addr, derived, err)
		}
	})

	t.Run("empty is derived", func(t *testing.T) {
		cfg := &Config{ListenAddr: "0.0.0.0:994"}
		addr, derived, err := resolveListenAddrV6(cfg)
		if err != nil {
			t.Fatalf("resolveListenAddrV6: %v", err)
		}
		if addr != "[::]:994" {
			t.Errorf("addr = %q, want [::]:994 following -listen", addr)
		}
		if !derived {
			t.Error("derived = false, want true so the log can say where the port came from")
		}
	})

	t.Run("empty with unparsable -listen disables v6", func(t *testing.T) {
		cfg := &Config{ListenAddr: "garbage"}
		addr, derived, err := resolveListenAddrV6(cfg)
		if err == nil {
			t.Fatalf("got %q, want an error so the caller skips the listener", addr)
		}
		if addr != "" || derived {
			t.Errorf("got (%q, %v) on error, want (\"\", false)", addr, derived)
		}
	})
}

// TestDerivedAddrIsBindable proves the derived string is something the IPv6
// listener can actually bind, and that it lands on the port -listen named. The
// port is taken from a throwaway listener so the test needs no root and no
// fixed port. Positive control for the table above: without it, every case
// there could agree on a string that net.Listen rejects.
func TestDerivedAddrIsBindable(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no usable IPv6 loopback here: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	addrV6, err := deriveListenAddrV6(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("deriveListenAddrV6: %v", err)
	}

	l, err := net.Listen("tcp6", addrV6)
	if err != nil {
		t.Fatalf("listening on derived %q: %v", addrV6, err)
	}
	defer l.Close()

	if got := l.Addr().(*net.TCPAddr).Port; got != port {
		t.Errorf("bound port %d, want %d from -listen", got, port)
	}
}
