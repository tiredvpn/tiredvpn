package endpoint

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SelectionPolicy decides which ENDPOINT the client prefers among the healthy
// ones. It is orthogonal to FamilyPolicy, which decides which address of a
// given endpoint is tried first: selection ranks servers, family ranks
// addresses inside one server.
type SelectionPolicy uint8

const (
	// SelectPriority keeps the configured order: the first endpoint wins until
	// it is parked. The default, and the only one that is fully predictable
	// from the config file alone.
	SelectPriority SelectionPolicy = iota
	// SelectLatency prefers the endpoint with the lowest measured round-trip
	// time. Endpoints with no measurement yet keep their configured order and
	// rank behind every measured one.
	SelectLatency
	// SelectWeighted draws the endpoint order once, at construction, with each
	// endpoint's chance proportional to its Weight.
	SelectWeighted
)

func (p SelectionPolicy) String() string {
	switch p {
	case SelectPriority:
		return "priority"
	case SelectLatency:
		return "latency"
	case SelectWeighted:
		return "weighted"
	default:
		return "unknown"
	}
}

// ParseSelectionPolicy maps the configuration spelling onto the policy.
func ParseSelectionPolicy(s string) (SelectionPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "priority", "":
		return SelectPriority, nil
	case "latency":
		return SelectLatency, nil
	case "weighted":
		return SelectWeighted, nil
	default:
		return SelectPriority, fmt.Errorf("endpoint: unknown selection policy %q", s)
	}
}

// Tuning is the operator-facing half of Config - everything that comes from the
// [selection] section of the config file. It carries no dialer and no clock, so
// the configuration layer can pass it around without depending on how the
// selector probes.
//
// Family is a pointer because its zero value (PreferV6) is a meaningful policy:
// nil means "not configured, derive it from the legacy flags", which is a
// different instruction from "the operator asked for prefer_v6".
type Tuning struct {
	Family           *FamilyPolicy
	Selection        SelectionPolicy
	FailureThreshold int
	Cooldown         time.Duration
	MinDwell         time.Duration
}

// FamilyOr returns the configured family policy, or fallback when the section
// left it unset.
func (t Tuning) FamilyOr(fallback FamilyPolicy) FamilyPolicy {
	if t.Family == nil {
		return fallback
	}
	return *t.Family
}

// config turns the tuning plus an endpoint list into a full selector Config.
// Zero-valued durations and counts stay zero so applyDefaults fills them.
func (t Tuning) config(eps []Endpoint, family FamilyPolicy) Config {
	return Config{
		Endpoints:        eps,
		Family:           family,
		Selection:        t.Selection,
		FailureThreshold: t.FailureThreshold,
		Cooldown:         t.Cooldown,
		MinDwell:         t.MinDwell,
		// Every caller of this path is a real client being built or rebuilt,
		// which is exactly the case candidate health has to survive.
		Shared: true,
	}
}

// NewTunedSelector builds a selector from an endpoint list and a [selection]
// section, using fallbackFamily when the section did not name one.
func NewTunedSelector(eps []Endpoint, t Tuning, fallbackFamily FamilyPolicy) (*Selector, error) {
	return NewSelector(t.config(eps, t.FamilyOr(fallbackFamily)))
}

// endpointOrder returns the endpoint indices in the order the selection policy
// wants them tried.
//
// It runs exactly once, in NewSelector. That is what makes SelectWeighted
// sticky: re-drawing per dial would send a client hopping between server IPs
// for no reason an observer could mistake for anything but a VPN looking for a
// way out.
func endpointOrder(eps []Endpoint, policy SelectionPolicy, rnd func() float64) []int {
	order := make([]int, len(eps))
	for i := range order {
		order[i] = i
	}
	if policy == SelectWeighted && len(eps) > 1 {
		return weightedOrder(eps, rnd)
	}
	// Priority and latency both start from the configured order. Latency
	// re-ranks later, from measurements that do not exist yet at construction.
	sort.SliceStable(order, func(a, b int) bool {
		return eps[order[a]].Order < eps[order[b]].Order
	})
	return order
}

// endpointWeight normalises Weight. A non-positive weight means "the operator
// did not say", not "never pick this one": an endpoint nobody can ever reach is
// expressed by leaving it out of the list.
func endpointWeight(e Endpoint) float64 {
	if e.Weight <= 0 {
		return 1
	}
	return float64(e.Weight)
}

// weightedOrder draws the whole order by successive weighted picks without
// replacement, so the fallback sequence is weighted too, not just the primary.
func weightedOrder(eps []Endpoint, rnd func() float64) []int {
	remaining := make([]int, len(eps))
	for i := range remaining {
		remaining[i] = i
	}
	sort.SliceStable(remaining, func(a, b int) bool {
		return eps[remaining[a]].Order < eps[remaining[b]].Order
	})

	out := make([]int, 0, len(eps))
	for len(remaining) > 0 {
		total := 0.0
		for _, idx := range remaining {
			total += endpointWeight(eps[idx])
		}
		pick := rnd() * total
		chosen := len(remaining) - 1
		acc := 0.0
		for pos, idx := range remaining {
			acc += endpointWeight(eps[idx])
			if pick < acc {
				chosen = pos
				break
			}
		}
		out = append(out, remaining[chosen])
		remaining = append(remaining[:chosen], remaining[chosen+1:]...)
	}
	return out
}
