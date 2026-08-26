package toml

import (
	"fmt"
	"strings"
	"time"
)

// ClientConfig is the root TOML schema for tiredvpn client.
type ClientConfig struct {
	Server   ClientServer   `toml:"server"`
	Servers  []ClientServer `toml:"servers,omitempty"`
	Strategy Strategy       `toml:"strategy"`
	Shaper   *ShaperConfig  `toml:"shaper,omitempty"`
	TLS      ClientTLS      `toml:"tls"`
	Logging  Logging        `toml:"logging"`

	// Selection tunes how the client picks among the servers above. It is a
	// pointer so "absent" is distinguishable from "all zero": absent means the
	// legacy CLI flags decide, all-zero would mean the same but says it
	// explicitly.
	Selection *Selection `toml:"selection,omitempty"`
}

// ClientServer holds one upstream tiredvpn endpoint.
//
// The same struct backs the single [server] table and every [[servers]]
// element: a lone [server] is defined to be a one-element list, so giving it a
// second shape would only create a second thing to keep in sync.
type ClientServer struct {
	// Name labels the endpoint in logs. Optional, but must be unique when set.
	Name string `toml:"name,omitempty"`

	Address string `toml:"address"`
	Port    int    `toml:"port"`

	// AddressV6 is the same server's IPv6 transport address, unbracketed
	// ("2001:db8::10"). PortV6 defaults to Port when omitted, because the
	// normal deployment listens on one port on both families.
	AddressV6 string `toml:"address_v6,omitempty"`
	PortV6    int    `toml:"port_v6,omitempty"`

	// Weight is reserved for the weighted selection policy. Ignored by the
	// priority policy, which is the only one implemented today.
	Weight int `toml:"weight,omitempty"`

	// Secret and SNI are per-endpoint overrides. Both are carried through to
	// the endpoint description; see internal/client.ResolveEndpoints for what
	// the runtime does with them today (a differing Secret is an error, not a
	// silent fallback to the global one).
	Secret string `toml:"secret,omitempty"`
	SNI    string `toml:"sni,omitempty"`
}

// hasAddress reports whether the entry names a server at all. A port on its own
// does not: it is the default that DefaultClient() puts there.
func (s ClientServer) hasAddress() bool {
	return s.Address != "" || s.AddressV6 != ""
}

// Selection is the [selection] block: which server to dial and when to give up
// on it.
//
// Durations are TOML strings ("1m", "30s") rather than integers, because a bare
// number in a config file is a unit waiting to be guessed wrong.
type Selection struct {
	// Policy orders the candidates: priority (config order), latency (fastest
	// measured first) or weighted (by Weight).
	Policy string `toml:"policy,omitempty"`

	// Family is the address-family policy: prefer_v6, prefer_v4, v6_only or
	// v4_only. Empty means "derive from the legacy -prefer-ipv6/-fallback-v4
	// flags", which is not the same as prefer_v6 - see
	// endpoint.FamilyPolicyFromLegacy.
	Family string `toml:"family,omitempty"`

	// FailureThreshold is how many failed connect cycles park a candidate.
	FailureThreshold int `toml:"failure_threshold,omitempty"`

	Cooldown    string `toml:"cooldown,omitempty"`
	MaxCooldown string `toml:"max_cooldown,omitempty"`
	MinDwell    string `toml:"min_dwell,omitempty"`

	// RecheckInterval is how often the background health check runs. It only
	// matters with HealthCheck = "active".
	RecheckInterval string `toml:"recheck_interval,omitempty"`

	// HealthCheck is "off" (default) or "active". It defaults to off on
	// purpose: walking a list of N servers on a timer is a periodic, fan-out
	// pattern with no cover traffic behind it - exactly the shape a censor
	// looks for.
	HealthCheck string `toml:"health_check,omitempty"`
}

// Selection policy / health-check spellings. Kept as constants so the
// validator, the CLI help and the runtime cannot drift apart.
const (
	PolicyPriority = "priority"
	PolicyLatency  = "latency"
	PolicyWeighted = "weighted"

	HealthCheckOff    = "off"
	HealthCheckActive = "active"
)

// ResolvedSelection is [selection] with durations parsed and spellings checked.
type ResolvedSelection struct {
	Policy           string
	Family           string
	FailureThreshold int
	Cooldown         time.Duration
	MaxCooldown      time.Duration
	MinDwell         time.Duration
	RecheckInterval  time.Duration
	HealthCheck      string

	// Zero-valued fields mean "unset, use the built-in default". The consumer
	// (internal/endpoint.Config) already applies defaults to every zero field,
	// so this layer deliberately does not invent its own.
}

// Resolve parses and validates the block. A nil receiver resolves to the zero
// value, i.e. defaults everywhere.
func (s *Selection) Resolve() (ResolvedSelection, error) {
	var out ResolvedSelection
	if s == nil {
		return out, nil
	}

	out.Policy = strings.ToLower(strings.TrimSpace(s.Policy))
	switch out.Policy {
	case "", PolicyPriority, PolicyLatency, PolicyWeighted:
	default:
		return out, fmt.Errorf("selection.policy: unknown value %q (want %s, %s or %s)",
			s.Policy, PolicyPriority, PolicyLatency, PolicyWeighted)
	}

	out.Family = strings.ToLower(strings.TrimSpace(s.Family))
	switch out.Family {
	case "", "prefer_v6", "prefer_v4", "v6_only", "v4_only":
	default:
		return out, fmt.Errorf("selection.family: unknown value %q (want prefer_v6, prefer_v4, v6_only or v4_only)", s.Family)
	}

	out.HealthCheck = strings.ToLower(strings.TrimSpace(s.HealthCheck))
	switch out.HealthCheck {
	case "", HealthCheckOff, HealthCheckActive:
	default:
		return out, fmt.Errorf("selection.health_check: unknown value %q (want %s or %s)",
			s.HealthCheck, HealthCheckOff, HealthCheckActive)
	}

	if s.FailureThreshold < 0 {
		return out, fmt.Errorf("selection.failure_threshold must be >= 0, got %d", s.FailureThreshold)
	}
	out.FailureThreshold = s.FailureThreshold

	type durField struct {
		name string
		raw  string
		dst  *time.Duration
	}
	for _, f := range []durField{
		{"cooldown", s.Cooldown, &out.Cooldown},
		{"max_cooldown", s.MaxCooldown, &out.MaxCooldown},
		{"min_dwell", s.MinDwell, &out.MinDwell},
		{"recheck_interval", s.RecheckInterval, &out.RecheckInterval},
	} {
		d, err := parseSelectionDuration(f.name, f.raw)
		if err != nil {
			return out, err
		}
		*f.dst = d
	}

	if out.MaxCooldown > 0 && out.Cooldown > 0 && out.MaxCooldown < out.Cooldown {
		return out, fmt.Errorf("selection.max_cooldown (%s) is shorter than selection.cooldown (%s)",
			out.MaxCooldown, out.Cooldown)
	}
	return out, nil
}

func parseSelectionDuration(name, raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("selection.%s: %w", name, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("selection.%s must not be negative, got %s", name, d)
	}
	return d, nil
}

// Strategy selects the TLS-mimicry transport. Concrete validation of the
// allowed values lives in the strategy package; here we only check non-empty.
type Strategy struct {
	Mode    string         `toml:"mode"`
	Options map[string]any `toml:"options,omitempty"`
}

// ClientTLS controls outbound TLS / fingerprint behavior.
type ClientTLS struct {
	ServerName         string   `toml:"server_name,omitempty"`
	Fingerprint        string   `toml:"fingerprint,omitempty"`
	ALPN               []string `toml:"alpn,omitempty"`
	InsecureSkipVerify bool     `toml:"insecure_skip_verify,omitempty"`
	CACert             string   `toml:"ca_cert,omitempty"`
}

// Logging controls log verbosity and destination.
type Logging struct {
	Level  string `toml:"level,omitempty"`
	Format string `toml:"format,omitempty"`
	Output string `toml:"output,omitempty"`
}

// ServerList returns the effective endpoint list: [[servers]] when present,
// otherwise the single [server] table, otherwise nil.
//
// Every consumer goes through this, so "a lone [server] is a one-element list"
// is a fact of the schema rather than a convention each caller re-implements.
func (c *ClientConfig) ServerList() []ClientServer {
	if len(c.Servers) > 0 {
		out := make([]ClientServer, len(c.Servers))
		copy(out, c.Servers)
		for i := range out {
			out[i].applyPortDefaults()
		}
		return out
	}
	if c.Server.hasAddress() {
		s := c.Server
		s.applyPortDefaults()
		return []ClientServer{s}
	}
	return nil
}

// DefaultPort is the port assumed for an entry that names an address and no
// port. It matches DefaultClient() and the -server flag's own habits.
const DefaultPort = 443

// applyPortDefaults fills the two ports that are allowed to be implicit:
// an omitted port is 443, and port_v6 follows port, because the normal
// deployment listens on one port on both families.
func (s *ClientServer) applyPortDefaults() {
	if s.Port == 0 {
		s.Port = DefaultPort
	}
	if s.PortV6 == 0 {
		s.PortV6 = s.Port
	}
}

// Validate runs semantic checks not enforced by TOML decoding alone.
func (c *ClientConfig) Validate() error {
	if len(c.Servers) > 0 && c.Server.hasAddress() {
		return fmt.Errorf("[server] and [[servers]] are mutually exclusive: " +
			"a lone [server] already means a one-element list, so keep one of the two")
	}

	list := c.ServerList()
	if len(list) == 0 {
		return fmt.Errorf("no server configured: set server.address (or address_v6), or add a [[servers]] entry")
	}

	seen := make(map[string]int, len(list))
	for i, s := range list {
		where := serverLabel(i, s.Name, len(c.Servers) > 0)
		if !s.hasAddress() {
			return fmt.Errorf("%s: address or address_v6 is required", where)
		}
		if s.Address != "" {
			if err := validatePort(where+".port", s.Port); err != nil {
				return err
			}
		}
		if s.AddressV6 != "" {
			if err := validatePort(where+".port_v6", s.PortV6); err != nil {
				return err
			}
		}
		if s.Name == "" {
			continue
		}
		if prev, dup := seen[s.Name]; dup {
			return fmt.Errorf("duplicate server name %q (entries %d and %d)", s.Name, prev, i)
		}
		seen[s.Name] = i
	}

	// strategy.mode is deliberately NOT required: an empty mode means "let the
	// manager pick", which is the default of the -strategy flag and the only
	// sane setting for a censorship-resistant client. Demanding it here made
	// automatic strategy selection unreachable from a config file.

	if _, err := c.Selection.Resolve(); err != nil {
		return err
	}
	if err := c.Shaper.validate(); err != nil {
		return err
	}
	return nil
}

func serverLabel(i int, name string, isList bool) string {
	switch {
	case name != "":
		return fmt.Sprintf("servers[%d] (%s)", i, name)
	case isList:
		return fmt.Sprintf("servers[%d]", i)
	default:
		return "server"
	}
}

func validatePort(field string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s must be in 1..65535, got %d", field, port)
	}
	return nil
}
