package client

import (
	"fmt"
	"os"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ServerSpec is one configured endpoint, as it arrives from [[servers]] in the
// TOML or from the -server/-server-v6 flags.
//
// Addr and AddrV6 are complete "host:port" strings (the v6 one bracketed),
// because that is the form every layer below - strategies, connectivity gate,
// TUN bypass - already passes around.
type ServerSpec struct {
	Name   string
	Addr   string
	AddrV6 string
	Weight int

	// Secret and SNI are per-endpoint overrides from the config file. See
	// ResolveEndpoints for what is and is not honoured today.
	Secret string
	SNI    string
}

// SelectionSpec is the runtime form of the [selection] block: durations
// parsed, spellings already validated by the config layer.
type SelectionSpec struct {
	// Policy orders candidates: priority (config order), latency or weighted.
	// Empty means priority.
	Policy string

	// Family is the address-family policy spelling. Empty means "derive from
	// the legacy PreferIPv6/FallbackToV4 fields", which is NOT the same as
	// prefer_v6: PreferIPv6=false has always meant IPv4 and no v6 probe at all.
	Family string

	FailureThreshold int
	Cooldown         time.Duration
	MaxCooldown      time.Duration
	MinDwell         time.Duration
	RecheckInterval  time.Duration

	// HealthCheck is "off" (default) or "active".
	HealthCheck string
}

// ResolveEndpoints turns the configured servers into the endpoint list the
// strategy manager selects from.
//
// It also writes back cfg.ServerAddr / cfg.ServerAddrV6 from the first
// endpoint. That write-back is the point of the function: those two fields are
// read by ControlConfig, tun.VPNConfig, the pool, JNI, macOS and the
// benchmarks, and keeping them meaning "the first endpoint" is what lets a
// server list land without touching five platform paths.
//
// It is pure apart from that write-back, does no I/O, and is safe to call more
// than once - Run, buildManager and runTUNMode each call it and must agree.
func ResolveEndpoints(cfg *Config) ([]endpoint.Endpoint, error) {
	specs := cfg.Servers
	if len(specs) == 0 {
		if cfg.ServerAddr == "" && cfg.ServerAddrV6 == "" {
			return nil, fmt.Errorf("-server is required (or server.address / a [[servers]] entry in the config file)")
		}
		specs = []ServerSpec{{Name: "server", Addr: cfg.ServerAddr, AddrV6: cfg.ServerAddrV6}}
	}

	eps := make([]endpoint.Endpoint, 0, len(specs))
	for i, s := range specs {
		if s.Addr == "" && s.AddrV6 == "" {
			return nil, fmt.Errorf("servers[%d] (%s): no address configured", i, specName(i, s.Name))
		}
		eps = append(eps, endpoint.Endpoint{
			Name:   s.Name,
			V4:     s.Addr,
			V6:     s.AddrV6,
			Weight: s.Weight,
			Order:  i,
			Secret: s.Secret,
			SNI:    s.SNI,
		})
	}

	if err := reconcileSecrets(cfg, specs); err != nil {
		return nil, err
	}

	cfg.ServerAddr = eps[0].V4
	cfg.ServerAddrV6 = eps[0].V6
	return eps, nil
}

// reconcileSecrets validates the secrets across the server list and settles what
// the client's default secret is.
//
// Different secrets on different servers are legal: the secret in force is a
// property of the endpoint being dialled and travels with the dial (see
// internal/strategy/secret.go). -secret / TIREDVPN_SECRET is the default for
// entries that name none of their own, which is why the two no longer conflict.
//
// What stays an error is a list where some entries carry a secret, some do not,
// and there is no default for the ones that do not: that config has no answer
// for half its servers, and the likeliest cause is a missed line rather than an
// intent. With a default present the same shape is a deliberate "these two
// servers are special", so it is accepted.
//
// The one write-back: when nothing else named a default, the first entry's
// secret becomes it. That is what lets a config file be the only place a secret
// appears, and it also keeps resolveSecret's "no secret - using the insecure
// default" warning off a list where every entry does have one. No dial can reach
// the adopted value, because a default is only consulted for an endpoint without
// a secret and by then there are none.
func reconcileSecrets(cfg *Config, specs []ServerSpec) error {
	var withSecret, without []string
	common := ""
	for i, s := range specs {
		name := specName(i, s.Name)
		if s.Secret == "" {
			without = append(without, name)
			continue
		}
		withSecret = append(withSecret, name)
		if common == "" {
			common = s.Secret
		}
	}
	if common == "" {
		return nil
	}

	if defaultSecret(cfg) != "" {
		return nil
	}
	if len(without) > 0 {
		return fmt.Errorf("server %s sets a secret but %s does not, and no default is configured: "+
			"give every entry a secret, or set -secret / TIREDVPN_SECRET for the ones that have none",
			withSecret[0], without[0])
	}
	cfg.Secret = common
	return nil
}

// defaultSecret is the secret for endpoints that name none: the flag, then the
// environment. Deliberately without resolveSecret's insecure placeholder - this
// answers "did the operator configure a default", and the placeholder is what
// happens when the answer is no.
func defaultSecret(cfg *Config) string {
	if cfg.Secret != "" {
		return cfg.Secret
	}
	return os.Getenv("TIREDVPN_SECRET")
}

func specName(i int, name string) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("servers[%d]", i)
}

// allServerAddrs lists every transport address across all endpoints, IPv4
// first within each endpoint, in configuration order.
//
// A resolve failure here yields an empty list rather than an error: the caller
// is deep inside TUN setup, where the same configuration has already been
// resolved successfully twice, and the list is an optimisation for bypass
// routes rather than something the tunnel cannot start without.
func allServerAddrs(cfg *Config) []string {
	eps, err := ResolveEndpoints(cfg)
	if err != nil {
		log.Warn("TUN bypass: cannot list server addresses: %v", err)
		return nil
	}
	out := make([]string, 0, len(eps)*2)
	for _, e := range eps {
		if e.V4 != "" {
			out = append(out, e.V4)
		}
		if e.V6 != "" {
			out = append(out, e.V6)
		}
	}
	return out
}

// selectorConfig builds the endpoint.Config for the manager: the endpoint list
// plus the selection policy.
//
// Zero-valued tuning fields are left zero on purpose - endpoint.Config applies
// its own defaults to each, so a config file that says nothing gets the
// package's defaults rather than a second set copied over here.
func selectorConfig(cfg *Config, eps []endpoint.Endpoint) (endpoint.Config, error) {
	if err := validateSelection(cfg.Selection); err != nil {
		return endpoint.Config{}, err
	}
	family, err := resolveFamilyPolicy(cfg)
	if err != nil {
		return endpoint.Config{}, err
	}
	warnUnappliedSelection(cfg, eps)
	return endpoint.Config{
		Endpoints:        eps,
		Family:           family,
		FailureThreshold: cfg.Selection.FailureThreshold,
		Cooldown:         cfg.Selection.Cooldown,
		MaxCooldown:      cfg.Selection.MaxCooldown,
		MinDwell:         cfg.Selection.MinDwell,
	}, nil
}

// selectionPolicyName spells out the implicit default so a log line never
// reads policy=.
func selectionPolicyName(p string) string {
	if p == "" {
		return "priority"
	}
	return p
}

// validateSelection rejects misspelled policy names.
//
// The config loader checks the same strings, but the flags reach here without
// passing through it: -server-policy on a client with no -config would
// otherwise be accepted, ignored, and reported only as "not implemented yet".
func validateSelection(s SelectionSpec) error {
	switch s.Policy {
	case "", "priority", "latency", "weighted":
	default:
		return fmt.Errorf("-server-policy / selection.policy: unknown value %q (want priority, latency or weighted)", s.Policy)
	}
	switch s.HealthCheck {
	case "", "off", "active":
	default:
		return fmt.Errorf("selection.health_check: unknown value %q (want off or active)", s.HealthCheck)
	}
	if s.FailureThreshold < 0 {
		return fmt.Errorf("selection.failure_threshold must be >= 0, got %d", s.FailureThreshold)
	}
	if s.MaxCooldown > 0 && s.Cooldown > 0 && s.MaxCooldown < s.Cooldown {
		return fmt.Errorf("selection.max_cooldown (%s) is shorter than selection.cooldown (%s)", s.MaxCooldown, s.Cooldown)
	}
	return nil
}

// resolveFamilyPolicy picks the address-family policy.
//
// An explicit selection.family wins; with none, the legacy flag pair decides
// through the one table that owns that mapping. The empty string must be
// checked here rather than handed to ParseFamilyPolicy, which maps "" to
// prefer_v6 - that would turn a -prefer-ipv6=false client into a dual-family
// one on upgrade.
func resolveFamilyPolicy(cfg *Config) (endpoint.FamilyPolicy, error) {
	if cfg.Selection.Family == "" {
		return endpoint.FamilyPolicyFromLegacy(cfg.PreferIPv6, cfg.FallbackToV4), nil
	}
	p, err := endpoint.ParseFamilyPolicy(cfg.Selection.Family)
	if err != nil {
		return p, fmt.Errorf("selection.family: %w", err)
	}
	return p, nil
}

// warnUnappliedSelection says out loud which configured knobs the runtime does
// not act on yet. Accepting a key and ignoring it is how a client ends up
// dialling in a way its operator did not ask for and cannot see.
func warnUnappliedSelection(cfg *Config, eps []endpoint.Endpoint) {
	switch cfg.Selection.Policy {
	case "", "priority":
	default:
		log.Warn("selection.policy=%q is not implemented yet; candidates stay in configuration order",
			cfg.Selection.Policy)
	}
	if cfg.Selection.HealthCheck == "active" {
		log.Warn("selection.health_check=active is not implemented yet; " +
			"the client only learns about a server by dialling it")
	}
	if cfg.Selection.RecheckInterval > 0 && cfg.Selection.HealthCheck != "active" {
		log.Warn("selection.recheck_interval is set but health_check is off; it has no effect")
	}
	for i, e := range eps {
		if e.SNI != "" {
			log.Warn("servers[%d] (%s): per-server sni is recorded but not applied yet; "+
				"the cover host is process-wide (-cover)", i, specName(i, e.Name))
		}
		if e.Weight != 0 && cfg.Selection.Policy != "weighted" {
			log.Debug("servers[%d] (%s): weight=%d is only used by the weighted policy",
				i, specName(i, e.Name), e.Weight)
		}
	}
}
