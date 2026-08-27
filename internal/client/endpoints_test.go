package client

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestResolveEndpoints_LegacySingleServer is the compatibility test that
// matters for the fleet: production units are one ExecStart line with -server
// and no -config. They must come out of the endpoint layer with exactly one
// endpoint and an untouched ServerAddr.
func TestResolveEndpoints_LegacySingleServer(t *testing.T) {
	cfg := &Config{ServerAddr: "203.0.113.10:995"}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatalf("ResolveEndpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want exactly 1", len(eps))
	}
	if eps[0].V4 != "203.0.113.10:995" || eps[0].V6 != "" {
		t.Fatalf("endpoint = %+v", eps[0])
	}
	if cfg.ServerAddr != "203.0.113.10:995" {
		t.Fatalf("ServerAddr was rewritten to %q", cfg.ServerAddr)
	}

	// Called again by buildManager and by the TUN path; all three must agree.
	again, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatalf("second ResolveEndpoints: %v", err)
	}
	if len(again) != 1 || again[0] != eps[0] {
		t.Fatalf("not idempotent: %+v then %+v", eps, again)
	}
}

func TestResolveEndpoints_LegacyDualStack(t *testing.T) {
	cfg := &Config{ServerAddr: "203.0.113.10:995", ServerAddrV6: "[2001:db8::10]:995"}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatalf("ResolveEndpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("a dual-addressed server is ONE endpoint, got %d", len(eps))
	}
	if eps[0].V4 != "203.0.113.10:995" || eps[0].V6 != "[2001:db8::10]:995" {
		t.Fatalf("endpoint = %+v", eps[0])
	}
}

func TestResolveEndpoints_NoServer(t *testing.T) {
	_, err := ResolveEndpoints(&Config{})
	if err == nil {
		t.Fatal("a config with no server at all must fail")
	}
	if !strings.Contains(err.Error(), "-server") {
		t.Fatalf("error should point at the flag, got: %v", err)
	}
}

func TestResolveEndpoints_ListOrderAndWriteBack(t *testing.T) {
	cfg := &Config{
		// Stale values from a previous configuration: the list wins, and the
		// write-back is what keeps ControlConfig / VPNConfig / pool honest.
		ServerAddr:   "leftover:1",
		ServerAddrV6: "[::1]:1",
		Servers: []ServerSpec{
			{Name: "ams", Addr: "203.0.113.10:443", AddrV6: "[2001:db8::10]:443", Weight: 100},
			{Name: "fra", Addr: "203.0.113.20:443"},
			{Name: "v6only", AddrV6: "[2001:db8::30]:995"},
		},
	}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatalf("ResolveEndpoints: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(eps))
	}
	for i, want := range []string{"ams", "fra", "v6only"} {
		if eps[i].Name != want {
			t.Errorf("endpoint %d = %q, want %q (configuration order)", i, eps[i].Name, want)
		}
		if eps[i].Order != i {
			t.Errorf("endpoint %d has Order %d", i, eps[i].Order)
		}
	}
	if eps[0].Weight != 100 {
		t.Errorf("weight not carried: %+v", eps[0])
	}
	if cfg.ServerAddr != "203.0.113.10:443" || cfg.ServerAddrV6 != "[2001:db8::10]:443" {
		t.Fatalf("ServerAddr/V6 not rewritten from the first entry: %q / %q", cfg.ServerAddr, cfg.ServerAddrV6)
	}
}

func TestResolveEndpoints_EntryWithoutAddress(t *testing.T) {
	cfg := &Config{Servers: []ServerSpec{{Name: "ams", Addr: "203.0.113.10:443"}, {Name: "ghost"}}}
	_, err := ResolveEndpoints(cfg)
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("err = %v, want it to name the addressless entry", err)
	}
}

// TestResolveEndpoints_Secrets pins the rules a server list's secrets follow.
//
// Different secrets on different servers are legal now: the key travels with the
// dial rather than being baked into a strategy. What is left to check is the
// shape of the list - where the default comes from, and which shapes have no
// answer for half their servers.
func TestResolveEndpoints_Secrets(t *testing.T) {
	t.Run("differing secrets are kept per endpoint", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{Servers: []ServerSpec{
			{Name: "ams", Addr: "203.0.113.10:443", Secret: "one"},
			{Name: "fra", Addr: "203.0.113.20:443", Secret: "two"},
		}}
		eps, err := ResolveEndpoints(cfg)
		if err != nil {
			t.Fatalf("ResolveEndpoints: %v", err)
		}
		if eps[0].Secret != "one" || eps[1].Secret != "two" {
			t.Fatalf("secrets = %q/%q, want one/two", eps[0].Secret, eps[1].Secret)
		}
	})

	t.Run("secret on some entries only, with no default, is rejected", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{Servers: []ServerSpec{
			{Name: "ams", Addr: "203.0.113.10:443", Secret: "one"},
			{Name: "fra", Addr: "203.0.113.20:443"},
		}}
		if _, err := ResolveEndpoints(cfg); err == nil {
			t.Fatal("a half-configured secret must not fall back to the insecure placeholder silently")
		}
	})

	t.Run("secret on some entries only is fine with a default", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{
			Secret: "from-flag",
			Servers: []ServerSpec{
				{Name: "ams", Addr: "203.0.113.10:443", Secret: "override"},
				{Name: "fra", Addr: "203.0.113.20:443"},
			},
		}
		eps, err := ResolveEndpoints(cfg)
		if err != nil {
			t.Fatalf("ResolveEndpoints: %v", err)
		}
		if eps[0].Secret != "override" || eps[1].Secret != "" {
			t.Fatalf("secrets = %q/%q, want override and the default", eps[0].Secret, eps[1].Secret)
		}
		if cfg.Secret != "from-flag" {
			t.Fatalf("Secret = %q, want the flag left alone as the default", cfg.Secret)
		}
	})

	t.Run("one shared secret is adopted", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{Servers: []ServerSpec{
			{Name: "ams", Addr: "203.0.113.10:443", Secret: "shared"},
			{Name: "fra", Addr: "203.0.113.20:443", Secret: "shared"},
		}}
		if _, err := ResolveEndpoints(cfg); err != nil {
			t.Fatalf("ResolveEndpoints: %v", err)
		}
		if cfg.Secret != "shared" {
			t.Fatalf("Secret = %q, want the shared config secret", cfg.Secret)
		}
	})

	t.Run("-secret does not compete with a per-server secret", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{
			Secret:  "from-flag",
			Servers: []ServerSpec{{Name: "ams", Addr: "203.0.113.10:443", Secret: "from-file"}},
		}
		eps, err := ResolveEndpoints(cfg)
		if err != nil {
			t.Fatalf("ResolveEndpoints: %v", err)
		}
		if eps[0].Secret != "from-file" {
			t.Fatalf("endpoint secret = %q, want the per-server value to win its own dial", eps[0].Secret)
		}
		if cfg.Secret != "from-flag" {
			t.Fatalf("Secret = %q, want the flag kept as the default", cfg.Secret)
		}
	})

	t.Run("every entry with its own secret needs no flag", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		cfg := &Config{Servers: []ServerSpec{
			{Name: "ams", Addr: "203.0.113.10:443", Secret: "one"},
			{Name: "fra", Addr: "203.0.113.20:443", Secret: "two"},
		}}
		if _, err := ResolveEndpoints(cfg); err != nil {
			t.Fatalf("ResolveEndpoints: %v", err)
		}
		// The adopted default is never dialled with - every endpoint has its own
		// - but it must not be empty, or resolveSecret substitutes the insecure
		// placeholder and warns about a secret the operator did configure.
		if cfg.Secret == "" {
			t.Fatal("no default adopted: resolveSecret would fall back to the insecure placeholder")
		}
	})
}

func TestSelectorConfig_FamilyFromLegacyFlags(t *testing.T) {
	cases := []struct {
		name         string
		preferIPv6   bool
		fallbackToV4 bool
		want         endpoint.FamilyPolicy
	}{
		{"prefer v6 with fallback", true, true, endpoint.PreferV6},
		{"prefer v6 without fallback", true, false, endpoint.V6Only},
		{"no v6 preference, fallback on", false, true, endpoint.V4Only},
		{"no v6 preference, fallback off", false, false, endpoint.V4Only},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerAddr:   "203.0.113.10:443",
				ServerAddrV6: "[2001:db8::10]:443",
				PreferIPv6:   tc.preferIPv6,
				FallbackToV4: tc.fallbackToV4,
			}
			eps, err := ResolveEndpoints(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := selectorConfig(cfg, eps)
			if err != nil {
				t.Fatalf("selectorConfig: %v", err)
			}
			if got.Family != tc.want {
				t.Fatalf("family = %s, want %s", got.Family, tc.want)
			}
		})
	}
}

func TestSelectorConfig_ExplicitFamilyWins(t *testing.T) {
	cfg := &Config{
		ServerAddr:   "203.0.113.10:443",
		ServerAddrV6: "[2001:db8::10]:443",
		PreferIPv6:   false, // legacy flags say v4_only...
		FallbackToV4: true,
		Selection:    SelectionSpec{Family: "prefer_v4"}, // ...the file says otherwise
	}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := selectorConfig(cfg, eps)
	if err != nil {
		t.Fatalf("selectorConfig: %v", err)
	}
	if got.Family != endpoint.PreferV4 {
		t.Fatalf("family = %s, want prefer_v4 from selection.family", got.Family)
	}
}

func TestSelectorConfig_CarriesTuning(t *testing.T) {
	cfg := &Config{
		ServerAddr: "203.0.113.10:443",
		Selection: SelectionSpec{
			FailureThreshold: 5,
			Cooldown:         2 * time.Minute,
			MaxCooldown:      20 * time.Minute,
			MinDwell:         7 * time.Minute,
		},
	}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := selectorConfig(cfg, eps)
	if err != nil {
		t.Fatalf("selectorConfig: %v", err)
	}
	if got.FailureThreshold != 5 || got.Cooldown != 2*time.Minute ||
		got.MaxCooldown != 20*time.Minute || got.MinDwell != 7*time.Minute {
		t.Fatalf("tuning dropped on the way to the selector: %+v", got)
	}
}

func TestSelectorConfig_RejectsUnknownPolicy(t *testing.T) {
	cfg := &Config{ServerAddr: "203.0.113.10:443", Selection: SelectionSpec{Policy: "fastest"}}
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectorConfig(cfg, eps); err == nil {
		t.Fatal("an unknown policy must fail at startup, not be warned about and ignored")
	}
}

func TestAllServerAddrs(t *testing.T) {
	cfg := &Config{Servers: []ServerSpec{
		{Name: "ams", Addr: "203.0.113.10:443", AddrV6: "[2001:db8::10]:443"},
		{Name: "fra", Addr: "203.0.113.20:443"},
		{Name: "v6only", AddrV6: "[2001:db8::30]:995"},
	}}
	got := allServerAddrs(cfg)
	want := []string{"203.0.113.10:443", "[2001:db8::10]:443", "203.0.113.20:443", "[2001:db8::30]:995"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addr %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestLegacyStartupMakesNoExtraDials is the "no behaviour change" guard for
// the fleet: a unit whose whole configuration is -server must not gain a
// single connection from the endpoint layer.
//
// The listener is real, so the counter can actually observe a dial; the
// sub-test below dials it on purpose to prove the counter is not simply blind
// (an unarmed counter would report zero either way).
func TestLegacyStartupMakesNoExtraDials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()

	cfg := &Config{ServerAddr: ln.Addr().String(), PreferIPv6: true, FallbackToV4: true}
	mgr, err := buildManager(cfg, "secret")
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}
	if got := mgr.GetServerAddr(context.Background()); got != cfg.ServerAddr {
		t.Fatalf("GetServerAddr = %q, want the configured %q", got, cfg.ServerAddr)
	}
	// One address configured, one candidate: nothing new to dial, ever.
	if states := mgr.EndpointStates(); len(states) != 1 || states[0].Addr != cfg.ServerAddr {
		t.Fatalf("candidates = %+v, want exactly the configured address", states)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("inspecting the manager opened %d connections, want 0", n)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("building the client opened %d connections, want 0", n)
	}

	t.Run("positive control: the counter does see a dial", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c.Close()
		deadline := time.Now().Add(2 * time.Second)
		for accepted.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if accepted.Load() == 0 {
			t.Fatal("the accept counter missed a real connection: the zero above proves nothing")
		}
	})

	ln.Close()
	<-done
}
