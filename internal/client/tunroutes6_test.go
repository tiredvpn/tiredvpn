package client

import (
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// baseTunConfig is the minimum a TUN client needs to build a VPNConfig.
func baseTunConfig() *Config {
	return &Config{
		TunName:    "tiredvpn0",
		TunIP:      "10.8.0.2",
		TunPeerIP:  "10.8.0.1",
		ServerAddr: "203.0.113.10:443",
	}
}

// TestNewTUNVPNConfigRoutes6 is the callsite test for -tun-routes6: parsing the
// value and then not putting it into VPNConfig looks exactly like never passing
// the flag, which on the node this exists for means its IPv6 stays dead.
func TestNewTUNVPNConfigRoutes6(t *testing.T) {
	cfg := baseTunConfig()
	cfg.TunRoutes6 = "none"

	vpnCfg, err := newTUNVPNConfig(cfg, nil)
	if err != nil {
		t.Fatalf("newTUNVPNConfig: %v", err)
	}
	if !vpnCfg.IPv6Routes.OperatorManaged() {
		t.Fatal("-tun-routes6 did not reach VPNConfig")
	}
	nets, err := vpnCfg.IPv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 0 {
		t.Errorf("-tun-routes6=none still claims %v", nets)
	}
}

// TestNewTUNVPNConfigRoutes6List: an explicit list arrives intact.
func TestNewTUNVPNConfigRoutes6List(t *testing.T) {
	cfg := baseTunConfig()
	cfg.TunRoutes6 = "2001:db8::/32,2001:db9::/48"

	vpnCfg, err := newTUNVPNConfig(cfg, nil)
	if err != nil {
		t.Fatalf("newTUNVPNConfig: %v", err)
	}
	nets, err := vpnCfg.IPv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 2 || nets[0].String() != "2001:db8::/32" || nets[1].String() != "2001:db9::/48" {
		t.Errorf("IPv6Routes = %v, want the two prefixes as written", nets)
	}
}

// TestNewTUNVPNConfigRoutes6Unset: without the flag the tunnel keeps claiming
// all of IPv6. This is the half of the change that must NOT move — a laptop
// that stops installing the half-defaults is issue #55 again.
func TestNewTUNVPNConfigRoutes6Unset(t *testing.T) {
	vpnCfg, err := newTUNVPNConfig(baseTunConfig(), nil)
	if err != nil {
		t.Fatalf("newTUNVPNConfig: %v", err)
	}
	if vpnCfg.IPv6Routes.OperatorManaged() {
		t.Fatal("an unset -tun-routes6 was read as operator-managed")
	}
	nets, err := vpnCfg.IPv6Routes.Nets()
	if err != nil {
		t.Fatalf("Nets: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("default config claims %v, want the two half-defaults", nets)
	}
	if nets[0].String() != "::/1" || nets[1].String() != "8000::/1" {
		t.Errorf("default config claims %v, want [::/1 8000::/1]", nets)
	}
}

// TestNewTUNVPNConfigRoutes6BadSpec: a malformed prefix stops the client rather
// than leaving it running with routing the operator believes is in place.
func TestNewTUNVPNConfigRoutes6BadSpec(t *testing.T) {
	cfg := baseTunConfig()
	cfg.TunRoutes6 = "2001:db8:::/32"

	_, err := newTUNVPNConfig(cfg, nil)
	if err == nil {
		t.Fatal("a malformed prefix started the client anyway")
	}
	if !strings.Contains(err.Error(), "tun-routes6") {
		t.Errorf("error %q does not name the flag at fault", err)
	}
}

// TestNewTUNVPNConfigRoutes6NeedsDual: only dual-stack installs IPv6 routes, so
// naming destinations under a policy that never negotiates IPv6 is a
// contradiction the operator cannot see at runtime — the flag would just do
// nothing.
func TestNewTUNVPNConfigRoutes6NeedsDual(t *testing.T) {
	for _, policy := range []string{"off", "block"} {
		cfg := baseTunConfig()
		cfg.TunRoutes6 = "none"
		cfg.TunIPv6Policy = policy

		if _, err := newTUNVPNConfig(cfg, nil); err == nil {
			t.Errorf("-tun-routes6 with -tun-ipv6=%s was accepted", policy)
		}
	}

	// And the combination that does make sense is accepted.
	cfg := baseTunConfig()
	cfg.TunRoutes6 = "none"
	cfg.TunIPv6Policy = "dual"
	if _, err := newTUNVPNConfig(cfg, nil); err != nil {
		t.Errorf("-tun-routes6 with -tun-ipv6=dual was refused: %v", err)
	}
}

// TestDefaultPolicyIsStillDual guards the premise the validation above rests
// on: -tun-routes6 alone has to work, which it only does while the default
// policy negotiates dual-stack.
func TestDefaultPolicyIsStillDual(t *testing.T) {
	policy, err := tun.ParseIPv6Policy(tun.DefaultIPv6Policy)
	if err != nil {
		t.Fatalf("parse default policy: %v", err)
	}
	if policy != tun.IPv6PolicyDual {
		t.Fatalf("default -tun-ipv6 is %s; -tun-routes6 on its own would now be refused", policy)
	}
}
