package strategy

import (
	"context"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// Which key the client authenticates with is a property of the endpoint being
// dialled, not of the process. A strategy is built once at start-up and outlives
// any number of endpoint switches, so a secret copied into it at construction
// can only ever be right for whichever endpoint happened to be first.
//
// The secret in force therefore travels with the dial, on the context that
// already reaches every strategy's Connect and Probe. Two concurrent dials to
// two different endpoints then stay honest without a barrier: each reads the
// value its own caller put on its own context, and nothing shared is mutated.
// A conn that needs the secret after Connect returns (http_polling's poll loop,
// seqovl's decoy on first write) captures it at construction, which is the same
// snapshot rule one level down - per connection rather than per process.
//
// Nothing on the wire changes. The bytes of every handshake are what they were;
// only the key fed into them can now differ per endpoint.

type dialSecretKey struct{}

// withDialSecret returns ctx carrying secret as the key for this dial. An empty
// secret is not recorded, so a caller with nothing to say cannot blank out a
// value a wrapping caller already set.
func withDialSecret(ctx context.Context, secret []byte) context.Context {
	if len(secret) == 0 {
		return ctx
	}
	return context.WithValue(ctx, dialSecretKey{}, secret)
}

// dialSecret returns the secret this dial must authenticate with, falling back
// to the one the strategy was constructed with.
//
// The fallback is the whole single-server story: one -secret, no [[servers]]
// list, nothing on the context - and every strategy behaves exactly as it did
// before per-endpoint secrets existed. It is also what the unit tests and the
// benchmarks rely on, since they construct strategies directly and dial with a
// bare context.Background().
func dialSecret(ctx context.Context, fallback []byte) []byte {
	if ctx != nil {
		if s, ok := ctx.Value(dialSecretKey{}).([]byte); ok && len(s) > 0 {
			return s
		}
	}
	return fallback
}

// The address travels the same way. Most strategies resolve the server they
// dial through Manager.GetServerAddr rather than the target they are handed,
// and that used to read the pin at the moment of the call - so a pin that
// moved mid-dial (a concurrent Connect, the pre-flight gate, a health report)
// sent the handshake to one server keyed for another. The address the dial
// was decided for now rides the context next to its key, and GetServerAddr
// answers with it.
type dialAddrKey struct{}

// The endpoint's cover-name pool ([[servers]] sni / -reality-sni) rides the
// same way: decided with the address and the key, so a dial cannot send one
// endpoint's ClientHello with another endpoint's names.
type dialSNIKey struct{}

// sniPool is the context value for dialSNIKey. A struct, not a bare slice, so
// "this dial has no pool of its own" (nil list, present) is told apart from
// "nobody decided" (absent).
type sniPool struct{ list []string }

// dialSNIs returns the cover-name pool this dial was decided with; nil means
// the built-in one.
func dialSNIs(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(dialSNIKey{}).(sniPool)
	return p.list
}

// withDialCandidate returns ctx carrying cand's address, secret and SNI pool,
// decided together for this dial.
func (m *Manager) withDialCandidate(ctx context.Context, cand endpoint.Candidate) context.Context {
	ctx = withDialSecret(ctx, m.secretForCandidate(cand))
	ctx = context.WithValue(ctx, dialSNIKey{}, sniPool{m.sniForCandidate(cand)})
	return context.WithValue(ctx, dialAddrKey{}, cand.Addr)
}

// sniForCandidate returns the cover-name pool configured on cand's endpoint,
// nil for the built-in pool.
func (m *Manager) sniForCandidate(cand endpoint.Candidate) []string {
	sel := m.selector()
	if sel == nil {
		return nil
	}
	ep, ok := sel.Endpoint(cand)
	if !ok {
		return nil
	}
	return ep.SNI
}

// dialAddr returns the server address this dial was decided for, if a caller
// named one.
func dialAddr(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	a, ok := ctx.Value(dialAddrKey{}).(string)
	return a, ok && a != ""
}

// ensureDialSecret fills in the pinned endpoint's secret and address when the
// caller has not named them.
//
// dialEndpoints names them per candidate, which is the precise answer. Every
// other way into the strategy scan - reconnect after a network change, budget
// recycling, port-hop make-before-break, the periodic reprobe - dials whatever
// is pinned right now, so the pinned endpoint is the right answer for them, and
// this is the one place that has to say so. Both come from one read of the pin.
func (m *Manager) ensureDialSecret(ctx context.Context) context.Context {
	hasSecret := false
	if ctx != nil {
		s, ok := ctx.Value(dialSecretKey{}).([]byte)
		hasSecret = ok && len(s) > 0
	}
	_, hasAddr := dialAddr(ctx)
	hasSNI := false
	if ctx != nil {
		_, hasSNI = ctx.Value(dialSNIKey{}).(sniPool)
	}
	if hasSecret && hasAddr && hasSNI {
		return ctx
	}
	sel := m.selector()
	var cand endpoint.Candidate
	pinned := false
	if sel != nil {
		cand, pinned = sel.Current()
	}
	if !hasSecret {
		if pinned {
			ctx = withDialSecret(ctx, m.secretForCandidate(cand))
		} else {
			ctx = withDialSecret(ctx, m.defaultSecret())
		}
	}
	if !hasAddr && pinned {
		ctx = context.WithValue(ctx, dialAddrKey{}, cand.Addr)
	}
	if !hasSNI && pinned {
		ctx = context.WithValue(ctx, dialSNIKey{}, sniPool{m.sniForCandidate(cand)})
	}
	return ctx
}

// CurrentSecret returns the secret of the endpoint pinned right now, or the
// process-wide default when no endpoint carries one of its own.
func (m *Manager) CurrentSecret() []byte {
	sel := m.selector()
	if sel == nil {
		return m.defaultSecret()
	}
	cand, ok := sel.Current()
	if !ok {
		return m.defaultSecret()
	}
	return m.secretForCandidate(cand)
}

// secretForCandidate returns the secret configured on cand's endpoint, or the
// default when that endpoint has none.
func (m *Manager) secretForCandidate(cand endpoint.Candidate) []byte {
	sel := m.selector()
	if sel == nil {
		return m.defaultSecret()
	}
	ep, ok := sel.Endpoint(cand)
	if !ok || ep.Secret == "" {
		return m.defaultSecret()
	}
	return []byte(ep.Secret)
}

// defaultSecret returns the process-wide secret (-secret / TIREDVPN_SECRET, or
// the single value a config file gave every server).
func (m *Manager) defaultSecret() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.secret
}

// setDefaultSecret records the process-wide secret. Called once, from
// NewDefaultManager, before any dial can start.
func (m *Manager) setDefaultSecret(secret []byte) {
	m.mu.Lock()
	m.secret = secret
	m.mu.Unlock()
}
