package client

import (
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// TestValidateSelection walks every rejection branch. The flags reach
// selectorConfig without passing through the config loader, so a spelling this
// function lets through is silently ignored at runtime rather than refused at
// startup - which is the failure mode the validator exists to prevent.
func TestValidateSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    SelectionSpec
		wantErr string // substring the error must name; "" means it must pass
	}{
		{"empty is valid", SelectionSpec{}, ""},
		{"priority is valid", SelectionSpec{Policy: "priority"}, ""},
		{"latency is valid", SelectionSpec{Policy: "latency"}, ""},
		{"weighted is valid", SelectionSpec{Policy: "weighted"}, ""},
		{"healthcheck off is valid", SelectionSpec{HealthCheck: "off"}, ""},
		{"healthcheck active is valid", SelectionSpec{HealthCheck: "active"}, ""},
		{"cooldowns consistent is valid", SelectionSpec{Cooldown: time.Minute, MaxCooldown: 5 * time.Minute}, ""},

		{"unknown policy", SelectionSpec{Policy: "fastest"}, "policy"},
		{"unknown healthcheck", SelectionSpec{HealthCheck: "passive"}, "health_check"},
		{"negative failure threshold", SelectionSpec{FailureThreshold: -1}, "failure_threshold"},
		{"max cooldown below cooldown", SelectionSpec{Cooldown: 10 * time.Minute, MaxCooldown: time.Minute}, "max_cooldown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSelection(tc.spec)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSelection(%+v) = %v, want nil", tc.spec, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateSelection(%+v) = nil, want an error naming %q", tc.spec, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidateSelection_MaxCooldownGuardNeedsBoth pins the exact shape of the
// max<cooldown guard: it only fires when both values are set. A zero MaxCooldown
// means "use the default", and rejecting that as "shorter than cooldown" would
// refuse every config that tunes only the base cooldown.
func TestValidateSelection_MaxCooldownGuardNeedsBoth(t *testing.T) {
	// MaxCooldown zero, Cooldown set: the guard must stay quiet.
	if err := validateSelection(SelectionSpec{Cooldown: 10 * time.Minute}); err != nil {
		t.Fatalf("cooldown alone rejected: %v", err)
	}
	// Cooldown zero, MaxCooldown set: still quiet - nothing to compare against.
	if err := validateSelection(SelectionSpec{MaxCooldown: time.Second}); err != nil {
		t.Fatalf("max_cooldown alone rejected: %v", err)
	}
}

// TestSelectionPolicyName spells out the implicit default so a log line never
// reads policy=.
func TestSelectionPolicyName(t *testing.T) {
	if got := selectionPolicyName(""); got != "priority" {
		t.Fatalf("selectionPolicyName(\"\") = %q, want priority", got)
	}
	if got := selectionPolicyName("weighted"); got != "weighted" {
		t.Fatalf("selectionPolicyName(weighted) = %q, want it passed through", got)
	}
}

// TestResolveFamilyPolicy covers both arms: an explicit family is parsed, a
// misspelled one is refused with the key named, and an empty family falls
// through to the legacy flag mapping rather than ParseFamilyPolicy's "" default
// (which would upgrade a v4-only client to dual on the next release).
func TestResolveFamilyPolicy(t *testing.T) {
	t.Run("explicit family parsed", func(t *testing.T) {
		got, err := resolveFamilyPolicy(&Config{Selection: SelectionSpec{Family: "v6_only"}})
		if err != nil {
			t.Fatalf("resolveFamilyPolicy: %v", err)
		}
		if got != endpoint.V6Only {
			t.Fatalf("family = %s, want v6_only", got)
		}
	})

	t.Run("misspelled family is refused and named", func(t *testing.T) {
		_, err := resolveFamilyPolicy(&Config{Selection: SelectionSpec{Family: "ipv6ish"}})
		if err == nil {
			t.Fatal("a misspelled selection.family must fail, not be silently ignored")
		}
		if !strings.Contains(err.Error(), "selection.family") {
			t.Fatalf("error %q does not name selection.family", err)
		}
	})

	t.Run("empty family uses legacy flags, not the prefer_v6 default", func(t *testing.T) {
		// PreferIPv6=false legacy pair means v4_only. Handing "" to
		// ParseFamilyPolicy would instead yield prefer_v6.
		got, err := resolveFamilyPolicy(&Config{PreferIPv6: false, FallbackToV4: true})
		if err != nil {
			t.Fatalf("resolveFamilyPolicy: %v", err)
		}
		if got != endpoint.V4Only {
			t.Fatalf("family = %s, want v4_only from the legacy flags", got)
		}
	})
}

// TestSpecName names an anonymous entry by its index so an error can point at a
// specific line of the server list.
func TestSpecName(t *testing.T) {
	if got := specName(2, "ams"); got != "ams" {
		t.Fatalf("specName with a name = %q, want ams", got)
	}
	if got := specName(2, ""); got != "servers[2]" {
		t.Fatalf("specName without a name = %q, want servers[2]", got)
	}
}

// TestParseTunIPv6Policy pins the -tun-ipv6 -> dualStack-handshake mapping. Only
// "dual" negotiates IPv6 on the wire, so both "off" and "block" must map to
// false: block leaks nothing but negotiates nothing either, and sending the
// v0x04 handshake for it would ask the exit for an address the tunnel will not
// carry.
func TestParseTunIPv6Policy(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    bool
		wantErr bool
	}{
		{"", false, false},     // empty defaults to off
		{"off", false, false},
		{"dual", true, false},
		{"block", false, false},
		{"on", false, true},   // not a policy the parser knows
		{"DUAL", false, true}, // case-sensitive on purpose
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseTunIPv6Policy(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTunIPv6Policy(%q) = (%v, nil), want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTunIPv6Policy(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseTunIPv6Policy(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
