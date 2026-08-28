package strategy

import "github.com/tiredvpn/tiredvpn/internal/endpoint"

// SetEndpointSelection replaces the endpoint selector with one built from cfg.
//
// Candidate health is not discarded when cfg describes the same pool and the
// same policy: the selector comes from a process-scoped table, so a client
// rebuilt after a failed connect - which is what the Android service does on
// every retry - inherits what its predecessor measured instead of starting
// again at the first server in the pool.
//
// It is the richer sibling of SetEndpoints: that one takes a list and a family
// policy, this one takes the whole endpoint.Config, which is what a client
// configured through [selection] needs (failure threshold, cooldown ceiling,
// minimum dwell). Building a selector performs no I/O, so calling this right
// after NewDefaultManager costs a struct, not a dial.
//
// A cfg that yields no dialable candidate is an error and leaves the existing
// selector alone - dropping the client to no endpoints at all is strictly
// worse than keeping the one it was started with.
func (m *Manager) SetEndpointSelection(cfg endpoint.Config) error {
	sel, err := endpoint.NewSelector(cfg)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.endpoints = sel
	m.mu.Unlock()
	return nil
}
