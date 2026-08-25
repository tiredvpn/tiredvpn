// Package endpoint picks which (server, address family) pair the client dials.
//
// A dial target is a Candidate: one Endpoint on one Family. Falling back from
// IPv6 to IPv4 and moving from one server to another are then the same
// operation - step to the next candidate - so both share one health model, one
// cooldown policy and one set of tests.
//
// The package never dials on its own: the dialer and the clock are injected
// (Config.Dial, Config.Now), which is what makes the policy testable without a
// network and without sleeping.
package endpoint

import (
	"fmt"
	"sort"
	"strings"
)

// Family is an IP address family. The zero value is deliberately invalid so a
// forgotten field shows up as an error rather than silently meaning IPv4.
type Family uint8

const (
	FamilyV4 Family = iota + 1
	FamilyV6
)

func (f Family) String() string {
	switch f {
	case FamilyV4:
		return "v4"
	case FamilyV6:
		return "v6"
	default:
		return "invalid"
	}
}

// Network returns the net.Dial network name that pins the probe to this family.
// Pinning matters: dialing "tcp" against a dual-stack host lets the resolver
// pick, so a "v6 is up" verdict could be produced by an IPv4 connection.
func (f Family) Network() string {
	switch f {
	case FamilyV4:
		return "tcp4"
	case FamilyV6:
		return "tcp6"
	default:
		return "tcp"
	}
}

// Endpoint is one server, optionally reachable on both families.
//
// V4 and V6 are full "host:port" strings (IPv6 bracketed), matching the form
// every other layer - strategies, connectivity checker, TUN bypass - already
// passes around.
type Endpoint struct {
	Name   string
	V4     string
	V6     string
	Weight int
	Order  int

	// Secret and SNI are per-endpoint overrides. They are carried here so the
	// selector can hand a complete description to the caller, but nothing in
	// this package interprets them.
	Secret string
	SNI    string
}

// Addr returns the endpoint's address on family f, or "" when it has none.
func (e Endpoint) Addr(f Family) string {
	switch f {
	case FamilyV4:
		return e.V4
	case FamilyV6:
		return e.V6
	default:
		return ""
	}
}

// Label returns a human-readable endpoint name for logs.
func (e Endpoint) Label(idx int) string {
	if e.Name != "" {
		return e.Name
	}
	return fmt.Sprintf("endpoint-%d", idx)
}

// Candidate is one dial target. It is a comparable value type, so it can be a
// map key and can be compared with == in tests.
type Candidate struct {
	EndpointIdx int
	Family      Family
	Addr        string
}

func (c Candidate) String() string {
	return fmt.Sprintf("%s/%s", c.Addr, c.Family)
}

// FamilyPolicy says which families are eligible and in what order.
type FamilyPolicy uint8

const (
	// PreferV6 tries IPv6 first and falls back to IPv4.
	PreferV6 FamilyPolicy = iota
	// PreferV4 tries IPv4 first and falls back to IPv6.
	PreferV4
	// V6Only never touches IPv4.
	V6Only
	// V4Only never touches IPv6.
	V4Only
)

func (p FamilyPolicy) String() string {
	switch p {
	case PreferV6:
		return "prefer_v6"
	case PreferV4:
		return "prefer_v4"
	case V6Only:
		return "v6_only"
	case V4Only:
		return "v4_only"
	default:
		return "unknown"
	}
}

// ParseFamilyPolicy maps the configuration spelling onto the policy.
func ParseFamilyPolicy(s string) (FamilyPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "prefer_v6", "":
		return PreferV6, nil
	case "prefer_v4":
		return PreferV4, nil
	case "v6_only":
		return V6Only, nil
	case "v4_only":
		return V4Only, nil
	default:
		return PreferV6, fmt.Errorf("endpoint: unknown family policy %q", s)
	}
}

// FamilyPolicyFromLegacy maps the -prefer-ipv6 / -fallback-v4 flag pair onto a
// policy.
//
// The false row is v4_only, not prefer_v4, and that is not a typo: today
// -prefer-ipv6=false returns IPv4 and never probes IPv6 at all. Mapping it to
// prefer_v4 would hand those clients a fallback they never had, which is a
// behaviour change smuggled in through a table. prefer_v4 is reachable only
// from explicit configuration.
func FamilyPolicyFromLegacy(preferIPv6, fallbackToV4 bool) FamilyPolicy {
	if !preferIPv6 {
		return V4Only
	}
	if fallbackToV4 {
		return PreferV6
	}
	return V6Only
}

// families returns the families this policy allows, most preferred first.
func (p FamilyPolicy) families() []Family {
	switch p {
	case PreferV6:
		return []Family{FamilyV6, FamilyV4}
	case PreferV4:
		return []Family{FamilyV4, FamilyV6}
	case V6Only:
		return []Family{FamilyV6}
	case V4Only:
		return []Family{FamilyV4}
	default:
		return []Family{FamilyV6, FamilyV4}
	}
}

// buildCandidates expands endpoints into the ordered candidate list.
//
// The order is endpoint-major: every family of the first endpoint before the
// second endpoint's. Falling back within a server is cheaper than moving to
// another one (same secret, same bypass route, same latency profile), so it
// must be tried first.
func buildCandidates(endpoints []Endpoint, policy FamilyPolicy) []Candidate {
	order := make([]int, len(endpoints))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return endpoints[order[a]].Order < endpoints[order[b]].Order
	})

	families := policy.families()
	cands := make([]Candidate, 0, len(endpoints)*len(families))
	seen := make(map[string]bool, len(endpoints)*len(families))
	for _, idx := range order {
		for _, f := range families {
			addr := endpoints[idx].Addr(f)
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			cands = append(cands, Candidate{EndpointIdx: idx, Family: f, Addr: addr})
		}
	}
	return cands
}
