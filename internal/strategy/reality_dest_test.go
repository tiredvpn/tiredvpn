package strategy

import (
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
)

// TestSelectDestinationSpreadsUnderLoad is the regression test for the donor
// fallback. The old code returned getRussianSNIsStatic()[0] once every donor was
// inside its cooldown window, so a burst of dials — the normal case, since every
// CONNECT costs a fresh handshake — piled onto a single SNI and manufactured
// exactly the burst the per-SNI freeze looks for.
func TestSelectDestinationSpreadsUnderLoad(t *testing.T) {
	pool := []string{"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"}
	r := &REALITYStrategy{
		sniRotator:  evasion.NewSNIRotatorWithPool(pool, evasion.StrategyCooldown),
		destPool:    pool,
		recentDests: make(map[string]time.Time),
	}

	const dials = 40
	counts := make(map[string]int, len(pool))
	for range dials {
		dest, err := r.selectDestination(r.secret, nil)
		if err != nil {
			t.Fatalf("selectDestination: %v", err)
		}
		host, _, err := net.SplitHostPort(dest)
		if err != nil {
			t.Fatalf("destination %q is not host:port: %v", dest, err)
		}
		counts[host]++
	}

	for _, sni := range pool {
		if counts[sni] == 0 {
			t.Errorf("donor %s never selected across %d dials", sni, dials)
		}
	}
	// With a 4-donor pool the fairest split is 25% each. Allow a wide margin —
	// the point is that no donor absorbs the burst, not that the split is even.
	limit := dials / 2
	for sni, n := range counts {
		if n > limit {
			t.Errorf("donor %s took %d of %d dials (> %d): the burst is collapsing onto one SNI", sni, n, dials, limit)
		}
	}
	if len(counts) > len(pool) {
		t.Errorf("selected %d distinct donors, pool has %d — a donor came from outside the derived pool", len(counts), len(pool))
	}
}


// TestSetFingerprintRejectsUnknown makes sure a config typo cannot quietly
// change what we put on the wire.
func TestSetFingerprintRejectsUnknown(t *testing.T) {
	r := NewREALITYStrategy(nil, []byte("secret"))
	original := r.fingerprint

	r.SetFingerprint("")
	if r.fingerprint != original {
		t.Errorf("empty name changed the profile to %q", r.fingerprint)
	}

	r.SetFingerprint("netscape-navigator")
	if r.fingerprint != original {
		t.Errorf("unknown name changed the profile to %q", r.fingerprint)
	}

	r.SetFingerprint("chrome")
	if r.fingerprint != "chrome" {
		t.Errorf("known name not applied, profile is %q", r.fingerprint)
	}
}
