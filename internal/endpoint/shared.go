package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// A client is not a process.
//
// On Android the VPN service throws the Go client away whenever a connect
// fails and builds a new one inside the same process. Every verdict the
// selector had reached died with it, so the replacement started from the top of
// the pool and rediscovered the same dead server - which is how a pool of six
// servers produced sixty dials to one address and none to the other five. The
// failure threshold could never be crossed either: it counts failed cycles of
// ONE selector, and no selector lived long enough to see two.
//
// Selectors built with Config.Shared come from a process-scoped table keyed by
// their configuration, so a rebuilt client inherits the health its predecessor
// measured. On desktop, where the client outlives every reconnect, the table
// hands back the same instance that would have been built anyway.
const sharedSelectorTTL = 10 * time.Minute

type sharedEntry struct {
	sel  *Selector
	used time.Time
}

var (
	sharedMu  sync.Mutex
	sharedSel = map[string]*sharedEntry{}
)

// sharedSelectorFor returns the process-scoped selector for cfg, building it on
// first use. cfg must already have been through applyDefaults, so that two
// configs that resolve to the same policy share one entry.
func sharedSelectorFor(cfg Config) (*Selector, error) {
	key := sharedKey(cfg)

	// Wall clock on purpose. This measures how long the process has been idle,
	// which is not what cfg.Now measures - a test that injects a clock and
	// advances it by hours must not have its cached selector evicted.
	now := time.Now()

	sharedMu.Lock()
	defer sharedMu.Unlock()

	if e, ok := sharedSel[key]; ok && now.Sub(e.used) < sharedSelectorTTL {
		e.used = now
		return e.sel, nil
	}

	sel, err := newSelector(cfg)
	if err != nil {
		return nil, err
	}
	// An entry older than the TTL describes a network the device may have left
	// hours ago; drop those instead of letting the table grow with every
	// configuration the process has ever seen.
	for k, e := range sharedSel {
		if now.Sub(e.used) >= sharedSelectorTTL {
			delete(sharedSel, k)
		}
	}
	sharedSel[key] = &sharedEntry{sel: sel, used: now}
	return sel, nil
}

// sharedKey fingerprints everything about a Config that changes what the
// selector decides. A field left out here would let two different policies
// share one set of verdicts, so the fingerprint is covered by a test that
// perturbs each field in turn.
//
// The func fields (Dial, Now, Rand) are deliberately absent: they are not
// comparable, and a caller that injects them is describing HOW to measure, not
// WHAT to measure.
func sharedKey(cfg Config) string {
	h := sha256.New()
	fmt.Fprintf(h, "family=%d;selection=%d;threshold=%d;cooldown=%d;maxcooldown=%d;dwell=%d;jitter=%v;probe=%d;",
		cfg.Family, cfg.Selection, cfg.FailureThreshold,
		cfg.Cooldown, cfg.MaxCooldown, cfg.MinDwell, cfg.JitterFrac, cfg.ProbeTimeout)
	for _, e := range cfg.Endpoints {
		fmt.Fprintf(h, "ep(%q,%q,%q,%d,%d,%q,%q);", e.Name, e.V4, e.V6, e.Weight, e.Order, e.Secret, e.SNI)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ResetSharedSelectors empties the process-scoped table. Tests use it to keep
// one case from inheriting another's verdicts; production never calls it,
// because the point of the table is that it survives.
func ResetSharedSelectors() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	clear(sharedSel)
}
