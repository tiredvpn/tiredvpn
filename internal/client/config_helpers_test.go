package client

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/porthopping"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestResolveSecret covers the precedence flag > env > insecure default. Every
// tunnel derives its client ID from this value, so picking the wrong source
// means the server rejects the client with "client not found".
func TestResolveSecret(t *testing.T) {
	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "from-env")
		if got := resolveSecret(&Config{Secret: "from-flag"}); got != "from-flag" {
			t.Fatalf("resolveSecret = %q, want from-flag", got)
		}
	})

	t.Run("env used when flag empty", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "from-env")
		if got := resolveSecret(&Config{}); got != "from-env" {
			t.Fatalf("resolveSecret = %q, want from-env", got)
		}
	})

	t.Run("falls back to the insecure default", func(t *testing.T) {
		t.Setenv("TIREDVPN_SECRET", "")
		// The default is deliberately fixed and logged as INSECURE; changing it
		// silently would break every deployment that relies on it for a first
		// connect.
		if got := resolveSecret(&Config{}); got != "default-secret-change-me" {
			t.Fatalf("resolveSecret = %q, want the insecure default", got)
		}
	})
}

// TestApplyAdaptiveDefaults checks the zero-value fill-in. A zero
// ReprobeInterval would make the manager re-probe in a tight loop, and a zero
// circuit threshold would trip the breaker on the first failure.
func TestApplyAdaptiveDefaults(t *testing.T) {
	t.Run("zero values are filled", func(t *testing.T) {
		cfg := &Config{}
		applyAdaptiveDefaults(cfg)
		if cfg.ReprobeInterval != 5*time.Minute {
			t.Errorf("ReprobeInterval = %v, want 5m", cfg.ReprobeInterval)
		}
		if cfg.CircuitThreshold != 3 {
			t.Errorf("CircuitThreshold = %d, want 3", cfg.CircuitThreshold)
		}
		if cfg.CircuitResetTime != 5*time.Minute {
			t.Errorf("CircuitResetTime = %v, want 5m", cfg.CircuitResetTime)
		}
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
		cfg := &Config{
			ReprobeInterval:  time.Minute,
			CircuitThreshold: 7,
			CircuitResetTime: 30 * time.Second,
		}
		applyAdaptiveDefaults(cfg)
		if cfg.ReprobeInterval != time.Minute || cfg.CircuitThreshold != 7 || cfg.CircuitResetTime != 30*time.Second {
			t.Fatalf("defaults overwrote operator settings: %+v", cfg)
		}
	})
}

// TestResolveRTTProfile pins the lookup, including the fallback for a typo'd
// profile name: an unknown name must not disable masking (returning nil there
// would silently drop the feature the operator asked for).
func TestResolveRTTProfile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      Config
		wantNil  bool
		wantName string
	}{
		{"masking off", Config{RTTMaskingEnabled: false, RTTProfile: "moscow-yandex"}, true, ""},
		{"no profile named", Config{RTTMaskingEnabled: true, RTTProfile: ""}, true, ""},
		{"known profile", Config{RTTMaskingEnabled: true, RTTProfile: "moscow-vk"}, false, "moscow-vk"},
		{"unknown profile falls back", Config{RTTMaskingEnabled: true, RTTProfile: "atlantis"}, false, "moscow-yandex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRTTProfile(&tc.cfg)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("resolveRTTProfile = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("resolveRTTProfile = nil, want a profile")
			}
			if got.Name != tc.wantName {
				t.Fatalf("profile = %q, want %q", got.Name, tc.wantName)
			}
		})
	}

	t.Run("fallback is the shared default profile", func(t *testing.T) {
		got := resolveRTTProfile(&Config{RTTMaskingEnabled: true, RTTProfile: "nope"})
		if got != strategy.MoscowToYandexProfile {
			t.Fatalf("fallback = %v, want MoscowToYandexProfile", got)
		}
	})
}

// TestDecodeECHConfig covers the base64 gate. A malformed config must disable
// ECH rather than be handed to the TLS stack as garbage, which would make every
// handshake fail instead of just losing SNI encryption.
func TestDecodeECHConfig(t *testing.T) {
	payload := []byte{0xfe, 0x0d, 0x00, 0x41}
	encoded := base64.StdEncoding.EncodeToString(payload)

	t.Run("valid base64 decodes", func(t *testing.T) {
		cfg := &Config{ECHEnabled: true, ECHConfigB64: encoded}
		got := decodeECHConfig(cfg)
		if string(got) != string(payload) {
			t.Fatalf("decoded % x, want % x", got, payload)
		}
		if !cfg.ECHEnabled {
			t.Error("a valid config must leave ECH enabled")
		}
	})

	t.Run("garbage disables ECH", func(t *testing.T) {
		cfg := &Config{ECHEnabled: true, ECHConfigB64: "!!!not base64!!!"}
		if got := decodeECHConfig(cfg); got != nil {
			t.Fatalf("decoded % x, want nil", got)
		}
		// The flag flip matters: logEnabledFeatures and the manager both read
		// it, so leaving it true would advertise ECH with no config behind it.
		if cfg.ECHEnabled {
			t.Error("undecodable config must switch ECH off")
		}
	})

	t.Run("disabled or empty yields nil", func(t *testing.T) {
		if got := decodeECHConfig(&Config{ECHEnabled: false, ECHConfigB64: encoded}); got != nil {
			t.Errorf("ECH off returned % x, want nil", got)
		}
		if got := decodeECHConfig(&Config{ECHEnabled: true}); got != nil {
			t.Errorf("empty config returned % x, want nil", got)
		}
	})
}

// TestBuildPortHoppingConfig checks that an invalid range is dropped instead of
// reaching the hopper. A rejected config must yield nil, not a half-built one:
// NewPortHopper on a bad range would leave the client hopping onto ports the
// server never listens on.
func TestBuildPortHoppingConfig(t *testing.T) {
	base := Config{
		PortHoppingEnabled: true,
		PortHopRangeStart:  47000,
		PortHopRangeEnd:    48000,
		PortHopInterval:    60 * time.Second,
		PortHopStrategy:    "random",
		PortHopSeed:        "seed",
	}

	t.Run("disabled yields nil", func(t *testing.T) {
		cfg := base
		cfg.PortHoppingEnabled = false
		if got := buildPortHoppingConfig(&cfg); got != nil {
			t.Fatalf("buildPortHoppingConfig = %+v, want nil", got)
		}
	})

	t.Run("valid config is passed through", func(t *testing.T) {
		cfg := base
		got := buildPortHoppingConfig(&cfg)
		if got == nil {
			t.Fatal("buildPortHoppingConfig = nil for a valid range")
		}
		if got.PortRangeStart != 47000 || got.PortRangeEnd != 48000 {
			t.Errorf("range = %d-%d, want 47000-48000", got.PortRangeStart, got.PortRangeEnd)
		}
		if got.Strategy != porthopping.Strategy("random") {
			t.Errorf("strategy = %q, want random", got.Strategy)
		}
		if string(got.Seed) != "seed" {
			t.Errorf("seed = %q, want seed", got.Seed)
		}
		if !got.Enabled {
			t.Error("Enabled must be set on the built config")
		}
	})

	for _, tc := range []struct {
		name  string
		mutis func(*Config)
	}{
		{"inverted range", func(c *Config) { c.PortHopRangeStart, c.PortHopRangeEnd = 48000, 47000 }},
		{"start out of range", func(c *Config) { c.PortHopRangeStart = 0 }},
		{"end out of range", func(c *Config) { c.PortHopRangeEnd = 70000 }},
		{"negative interval", func(c *Config) { c.PortHopInterval = -time.Second }},
		{"unknown strategy", func(c *Config) { c.PortHopStrategy = "spiral" }},
	} {
		t.Run("rejected: "+tc.name, func(t *testing.T) {
			cfg := base
			tc.mutis(&cfg)
			if got := buildPortHoppingConfig(&cfg); got != nil {
				t.Fatalf("buildPortHoppingConfig = %+v, want nil for an invalid config", got)
			}
		})
	}
}

// TestSplitRoutes covers the -tun-routes parser. An empty element leaking
// through becomes an `ip route add ""` that fails the whole TUN setup.
func TestSplitRoutes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",,,", nil},
		{"0.0.0.0/0", []string{"0.0.0.0/0"}},
		{" 10.0.0.0/8 , 192.168.0.0/16 ", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"10.0.0.0/8,,172.16.0.0/12,", []string{"10.0.0.0/8", "172.16.0.0/12"}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := splitRoutes(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitRoutes(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("splitRoutes(%q) = %q, want %q", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestTruncate covers the log-line clamp used on proxy request lines.
func TestTruncate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{"shorter than limit", "GET /", 32, "GET /"},
		{"exactly at limit", "abcd", 4, "abcd"},
		{"over the limit", "abcdef", 4, "abcd..."},
		{"zero limit", "abc", 0, "..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.in, tc.maxLen); got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.maxLen, got, tc.want)
			}
		})
	}
}

// TestBufferedConnRead covers the protocol-sniffing wrapper: bytes already
// peeked off the wire must be replayed before the socket is read again, or the
// proxy handler loses the first request line it just parsed.
func TestBufferedConnRead(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		srv.Write([]byte("TAIL"))
		srv.Close()
	}()

	bc := &bufferedConn{Conn: cli, buffer: []byte("HEAD")}

	// Short reads must walk the buffer rather than restart it.
	got := make([]byte, 2)
	if n, err := bc.Read(got); err != nil || n != 2 || string(got[:n]) != "HE" {
		t.Fatalf("first read = %q (n=%d, err=%v), want HE", got[:n], n, err)
	}
	if n, err := bc.Read(got); err != nil || n != 2 || string(got[:n]) != "AD" {
		t.Fatalf("second read = %q (n=%d, err=%v), want AD", got[:n], n, err)
	}

	// Buffer drained: the next read has to come off the real connection.
	rest := make([]byte, 4)
	if n, err := bc.Read(rest); err != nil || string(rest[:n]) != "TAIL" {
		t.Fatalf("post-buffer read = %q (n=%d, err=%v), want TAIL", rest[:n], n, err)
	}
}

// TestBuildManagerRejectsUnknownStrategy pins the -strategy validation: an
// unknown ID must fail loudly at startup instead of silently leaving the
// manager on its adaptive default.
func TestBuildManagerRejectsUnknownStrategy(t *testing.T) {
	t.Run("unknown name errors", func(t *testing.T) {
		cfg := &Config{ServerAddr: "127.0.0.1:995", StrategyName: "definitely-not-a-strategy"}
		if _, err := buildManager(cfg, "secret"); err == nil {
			t.Fatal("buildManager = nil error for an unknown strategy")
		}
	})

	t.Run("no forced strategy builds", func(t *testing.T) {
		cfg := &Config{ServerAddr: "127.0.0.1:995", ServerAddrV6: "[::1]:995", PreferIPv6: true}
		mgr, err := buildManager(cfg, "secret")
		if err != nil {
			t.Fatalf("buildManager: %v", err)
		}
		if mgr == nil {
			t.Fatal("buildManager returned a nil manager with no error")
		}
	})
}
