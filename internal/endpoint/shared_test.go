package endpoint

import (
	"testing"
	"time"
)

func sharedTestEndpoints() []Endpoint {
	return []Endpoint{
		{Name: "a", V4: "198.51.100.1:443", V6: "[2001:db8::1]:443", Order: 0, Weight: 1, Secret: "s1", SNI: "a.example"},
		{Name: "b", V4: "198.51.100.2:443", Order: 1, Weight: 2},
	}
}

// TestSharedSelectorIsReusedForTheSameConfig is the property the Android
// lifecycle depends on: a client rebuilt from the same configuration must get
// the selector its predecessor was using, not a blank one.
func TestSharedSelectorIsReusedForTheSameConfig(t *testing.T) {
	ResetSharedSelectors()
	t.Cleanup(ResetSharedSelectors)

	cfg := Config{Endpoints: sharedTestEndpoints(), Shared: true}

	first, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	second, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	if first != second {
		t.Fatal("a rebuilt client got a fresh selector, losing every verdict the previous one reached")
	}

	// Without the opt-in nothing is shared, which is what every existing
	// caller and every test that injects its own clock relies on.
	private, err := NewSelector(Config{Endpoints: sharedTestEndpoints()})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	if private == first {
		t.Fatal("a selector built without Shared came out of the shared table")
	}
}

// TestSharedSelectorVerdictsSurviveRebuild checks the thing the sharing is for,
// not merely that the pointer matches: a failure recorded by one client is
// still in force for the next.
func TestSharedSelectorVerdictsSurviveRebuild(t *testing.T) {
	ResetSharedSelectors()
	t.Cleanup(ResetSharedSelectors)

	cfg := Config{Endpoints: sharedTestEndpoints(), Family: V4Only, Shared: true}

	first, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	cand, _ := first.Current()
	first.ReportSilent(cand)

	second, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	next, ok := second.Reconsider(second.Now())
	if !ok {
		t.Fatal("Reconsider found no candidate")
	}
	if next.Addr == cand.Addr {
		t.Fatalf("the rebuilt client went straight back to %s, which the previous one had just parked", cand.Addr)
	}
}

// TestSharedKeySeparatesEveryPolicyField perturbs each field of Config in turn.
// A field missing from the fingerprint would let two different policies share
// one set of verdicts - a client configured with a one-minute cooldown would
// inherit the parking decisions of one configured with thirty.
//
// Endpoints are covered field by field too, because a pool that differs only in
// weight or in per-endpoint secret is a different pool.
func TestSharedKeySeparatesEveryPolicyField(t *testing.T) {
	base := Config{Endpoints: sharedTestEndpoints()}
	base.applyDefaults()

	v6 := V6Only
	cases := map[string]func(c *Config){
		"family":           func(c *Config) { c.Family = v6 },
		"selection":        func(c *Config) { c.Selection = SelectLatency },
		"failureThreshold": func(c *Config) { c.FailureThreshold++ },
		"cooldown":         func(c *Config) { c.Cooldown += time.Second },
		"maxCooldown":      func(c *Config) { c.MaxCooldown += time.Second },
		"minDwell":         func(c *Config) { c.MinDwell += time.Second },
		"jitterFrac":       func(c *Config) { c.JitterFrac += 0.05 },
		"probeTimeout":     func(c *Config) { c.ProbeTimeout += time.Second },
		"endpointCount":    func(c *Config) { c.Endpoints = c.Endpoints[:1] },
		"endpointName":     func(c *Config) { c.Endpoints[0].Name = "other" },
		"endpointV4":       func(c *Config) { c.Endpoints[0].V4 = "198.51.100.9:443" },
		"endpointV6":       func(c *Config) { c.Endpoints[0].V6 = "[2001:db8::9]:443" },
		"endpointWeight":   func(c *Config) { c.Endpoints[0].Weight += 7 },
		"endpointOrder":    func(c *Config) { c.Endpoints[0].Order += 7 },
		"endpointSecret":   func(c *Config) { c.Endpoints[0].Secret = "other" },
		"endpointSNI":      func(c *Config) { c.Endpoints[0].SNI = "other.example" },
	}

	baseKey := sharedKey(base)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			c.Endpoints = sharedTestEndpoints()
			mutate(&c)
			if got := sharedKey(c); got == baseKey {
				t.Fatalf("changing %s left the fingerprint unchanged: two different policies would share one selector", name)
			}
		})
	}

	// The control: an untouched copy must still land on the same entry, or the
	// test above would pass for a fingerprint that is simply random.
	same := base
	same.Endpoints = sharedTestEndpoints()
	if got := sharedKey(same); got != baseKey {
		t.Fatal("an identical config fingerprinted differently - nothing would ever be shared")
	}
}

// TestSharedSelectorExpires: a phone that spent the night in a pocket must not
// wake up still parking servers it last measured on a network it has left.
func TestSharedSelectorExpires(t *testing.T) {
	ResetSharedSelectors()
	t.Cleanup(ResetSharedSelectors)

	cfg := Config{Endpoints: sharedTestEndpoints(), Shared: true}
	first, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}

	sharedMu.Lock()
	for _, e := range sharedSel {
		e.used = e.used.Add(-sharedSelectorTTL - time.Minute)
	}
	sharedMu.Unlock()

	second, err := NewSelector(cfg)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	if second == first {
		t.Fatal("a selector older than the TTL was handed out again")
	}
}
