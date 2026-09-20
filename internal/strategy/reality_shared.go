package strategy

import (
	"sync"

	"github.com/tiredvpn/tiredvpn/internal/evasion"
)

// realityShared holds the handshake-discipline state that every REALITY
// strategy built over one Manager must share: a single handshake gate and one
// donor pool/rotator per secret.
//
// Without sharing, a client that runs both the baseline REALITY strategy and
// the seqovl strategy (which rides its own REALITY handshake) ends up with two
// gates and two rotators. The gate enforces "at most two handshakes in flight
// per SNI" and a 250 ms spacing; with two of them the real ceiling to one donor
// SNI doubles to four and the spacing is no longer coordinated - exactly the
// per-SNI burst TSPU keys on. The rotators would also walk the donor cycle out
// of step. Keying on the Manager makes all REALITY instances of one client
// process share one set.
type realityShared struct {
	gate *handshakeGate

	mu     sync.Mutex
	donors map[string]*donorSet // keyed by secret; includes the construction secret
}

func newRealityShared() *realityShared {
	return &realityShared{
		gate:   newHandshakeGate(),
		donors: make(map[string]*donorSet),
	}
}

// donorSetFor returns the pool+rotator for secret, deriving and caching it once
// per secret so two REALITY instances on the same Manager walk the same rotator.
func (s *realityShared) donorSetFor(secret []byte) *donorSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.donors[string(secret)]; ok {
		return d
	}
	d := &donorSet{}
	d.pool, d.rotator = buildDonorSet(secret)
	s.donors[string(secret)] = d
	return d
}

// buildDonorSet derives the cover-domain pool for a secret and a cooldown
// rotator over it. Kept here so the constructor and the per-secret cache share
// one derivation instead of two copies drifting apart.
func buildDonorSet(secret []byte) ([]string, *evasion.SNIRotator) {
	developerPool := make([]string, 0, 8)
	for _, entry := range evasion.WhitelistedSNIs {
		if entry.Category == "developer" {
			developerPool = append(developerPool, entry.SNI)
		}
	}
	pool := derivePool(developerPool, secret, len(developerPool))
	if len(pool) == 0 {
		// Fallback to the legacy Tier 1 list if derivation yields nothing.
		pool = getRussianSNIsStatic()
	}
	return pool, evasion.NewSNIRotatorWithPool(pool, evasion.StrategyCooldown)
}

var (
	realitySharedMu sync.Mutex
	realitySharedBy = map[*Manager]*realityShared{}
)

// sharedRealityState returns the shared handshake state for a Manager, creating
// it on first use. A nil Manager (direct construction in tests) gets a fresh
// standalone set that is not retained, so those instances stay isolated from
// each other exactly as before.
func sharedRealityState(m *Manager) *realityShared {
	if m == nil {
		return newRealityShared()
	}
	realitySharedMu.Lock()
	defer realitySharedMu.Unlock()
	s, ok := realitySharedBy[m]
	if !ok {
		s = newRealityShared()
		realitySharedBy[m] = s
	}
	return s
}
