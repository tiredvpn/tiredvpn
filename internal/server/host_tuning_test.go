package server

import (
	"flag"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"testing"
)

var updateHostTuningDocs = flag.Bool("update-host-tuning-docs", false, "rewrite the Host tuning table in docs/server.md from hostTuningRules")

// fakeHost is a host whose sysctls are a map. A missing key reads as a missing
// /proc file.
type fakeHost struct {
	sysctls  map[string]string
	nofile   uint64
	ram      uint64
	limit    uint64 // 0 = no memory limit on the unit
	limitErr error
}

func (f fakeHost) sysctl(name string) (string, error) {
	v, ok := f.sysctls[name]
	if !ok {
		return "", fmt.Errorf("open /proc/sys/%s: %w", strings.ReplaceAll(name, ".", "/"), os.ErrNotExist)
	}
	return v, nil
}

func (f fakeHost) nofileSoft() (uint64, error) { return f.nofile, nil }
func (f fakeHost) memTotal() (uint64, error)   { return f.ram, nil }
func (f fakeHost) memLimit() (uint64, bool, error) {
	return f.limit, f.limit != 0, f.limitErr
}

const (
	gib       = 1 << 30
	stockRAM2 = 2023380 * 1024 // a 2 GB node, MemTotal as read on 2026-10-24
	stockRAM1 = 983276 * 1024  // the 960 MB node
)

// tunedHost satisfies every rule for every config used below.
func tunedHost(override map[string]string) fakeHost {
	h := fakeHost{nofile: 524287, ram: stockRAM2, sysctls: map[string]string{
		"net.core.rmem_max":                         "16777216",
		"net.core.wmem_max":                         "16777216",
		"net.ipv4.tcp_mem":                          "21582\t28777\t43164",
		"net.ipv4.tcp_congestion_control":           "bbr",
		"net.ipv4.tcp_available_congestion_control": "reno cubic bbr",
		"net.ipv4.ip_forward":                       "1",
		"net.ipv6.conf.all.forwarding":              "1",
		"net.netfilter.nf_conntrack_max":            "262144",
		"net.core.somaxconn":                        "4096",
	}}
	for k, v := range override {
		if v == "<missing>" {
			delete(h.sysctls, k)
			continue
		}
		h.sysctls[k] = v
	}
	return h
}

var (
	cfgExit      = &Config{IPPoolNetwork: "10.8.0.0/24"}
	cfgExitWide  = &Config{IPPoolNetwork: "10.8.0.0/16"}
	cfgExitQUIC  = &Config{IPPoolNetwork: "10.8.0.0/24", QUICEnabled: true}
	cfgProxyOnly = &Config{}
	cfgRelay     = &Config{UpstreamAddr: "exit.invalid:443", IPPoolNetwork: "10.9.1.0/24"}
	cfgRelayBig  = &Config{UpstreamAddr: "exit.invalid:443", IPPoolNetwork: "10.9.1.0/24", RelayUpstreamBufBytes: 2 << 20}
)

// adviceFor returns the advice line for setting and whether it was logged at
// INFO, or "" when the rule did not fire.
func adviceFor(rep hostTuningReport, setting string) (line string, info bool) {
	match := func(l string) bool {
		return strings.HasPrefix(l, "Host tuning: "+setting+" is ") || strings.HasPrefix(l, "Host tuning (unmeasured): "+setting+" is ")
	}
	for _, l := range rep.info {
		if match(l) {
			return l, true
		}
	}
	for _, l := range rep.debug {
		if match(l) {
			return l, false
		}
	}
	return "", false
}

func ruleBasis(setting string) string {
	for _, r := range hostTuningRules {
		if r.setting == setting {
			return r.basis
		}
	}
	return ""
}

// hostTuningCase is one host + config and the verdict expected for one rule.
type hostTuningCase struct {
	name      string
	cfg       *Config
	dualStack bool
	override  map[string]string
	nofile    uint64
	ram       uint64
	limit     uint64
	setting   string
	// want is the recommended value when the rule must fire, "" when it must
	// stay silent.
	want string
	// wantIn are further substrings the fired line must contain.
	wantIn []string
	// wantOut must not appear in the fired line.
	wantOut []string
}

var hostTuningCases = []hostTuningCase{
	// rmem_max / wmem_max: relays only, against the upstream buffer, within
	// the memory budget.
	{name: "relay default buf, rmem 1MiB: fine", cfg: cfgRelay, override: map[string]string{"net.core.rmem_max": "1048576"}, setting: "net.core.rmem_max"},
	{name: "relay default buf, stock rmem: fires at 512K", cfg: cfgRelay, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max", want: "524288",
		wantIn: []string{"is 212992", "upstream dialer requests 524288-byte", "Fix: on the host, sysctl -w net.core.rmem_max=524288, then restart the server", "'net.core.rmem_max = 524288' to /etc/sysctl.d/90-tiredvpn.conf"}},
	{name: "relay -relay-upstream-buf 2MiB, rmem 1MiB: fires at 2MiB", cfg: cfgRelayBig, override: map[string]string{"net.core.rmem_max": "1048576"}, setting: "net.core.rmem_max", want: "2097152"},
	{name: "relay, rmem exactly 512K: fine", cfg: cfgRelay, override: map[string]string{"net.core.rmem_max": "524288"}, setting: "net.core.rmem_max"},
	{name: "exit, stock rmem: exits are not advised", cfg: cfgExit, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max"},
	{name: "exit with QUIC, stock rmem: exits are not advised", cfg: cfgExitQUIC, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max"},
	{name: "relay under MemoryMax 800M: fits, fires", cfg: cfgRelay, limit: 800 << 20, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max", want: "524288"},
	{name: "relay under MemoryMax 100M: held back", cfg: cfgRelay, limit: 100 << 20, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max",
		want:    "524288 only after the memory budget allows it",
		wantIn:  []string{"more than half of this unit's memory limit (MemoryMax) (100 MiB)", "Fix: raise the memory limit to at least", "leave net.core.rmem_max as it is"},
		wantOut: []string{"sysctl -w", "persist"}},
	{name: "relay, MemoryMax above host RAM: host RAM is the budget", cfg: cfgRelay, limit: 64 * gib, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max", want: "524288"},
	{name: "relay, tcp_mem unreadable, MemoryMax 800M: 256 x 2 MiB does not fit", cfg: cfgRelay, limit: 800 << 20, override: map[string]string{"net.core.rmem_max": "212992", "net.ipv4.tcp_mem": "<missing>"}, setting: "net.core.rmem_max",
		want: "524288 only after the memory budget allows it", wantIn: []string{"could take 512 MiB"}},
	{name: "relay, tcp_mem bounds the estimate, MemoryMax 800M: fits", cfg: &Config{UpstreamAddr: "exit.invalid:443", MaxConcurrentConns: 100000}, limit: 800 << 20, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max", want: "524288"},

	{name: "relay, stock wmem: fires", cfg: cfgRelay, override: map[string]string{"net.core.wmem_max": "212992"}, setting: "net.core.wmem_max", want: "524288"},
	{name: "relay, wmem exactly 512K: fine", cfg: cfgRelay, override: map[string]string{"net.core.wmem_max": "524288"}, setting: "net.core.wmem_max"},
	{name: "exit, stock wmem: exits are not advised", cfg: cfgExit, override: map[string]string{"net.core.wmem_max": "212992"}, setting: "net.core.wmem_max"},
	{name: "relay under MemoryMax 100M, stock wmem: held back", cfg: cfgRelay, limit: 100 << 20, override: map[string]string{"net.core.wmem_max": "212992"}, setting: "net.core.wmem_max", want: "524288 only after the memory budget allows it"},

	// bbr
	{name: "cubic, bbr not loaded: fires with modprobe", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "reno cubic"}, setting: "net.ipv4.tcp_congestion_control", want: "bbr",
		wantIn: []string{"Fix: on the host, modprobe tcp_bbr && sysctl -w net.ipv4.tcp_congestion_control=bbr, then restart the server", "/etc/modules-load.d/tiredvpn.conf", "changes every TCP flow on the host"}},
	{name: "cubic, bbr available: fires without modprobe", cfg: cfgRelay, override: map[string]string{"net.ipv4.tcp_congestion_control": "cubic"}, setting: "net.ipv4.tcp_congestion_control", want: "bbr",
		wantIn: []string{"Fix: on the host, sysctl -w net.ipv4.tcp_congestion_control=bbr, then restart"}, wantOut: []string{"modprobe"}},
	{name: "cubic, only bbr2 available: modprobe for bbr", cfg: cfgRelay, override: map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "reno cubic bbr2"}, setting: "net.ipv4.tcp_congestion_control", want: "bbr", wantIn: []string{"modprobe tcp_bbr"}},
	{name: "bbr: fine", cfg: cfgExit, setting: "net.ipv4.tcp_congestion_control"},
	{name: "bbr2: fine", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_congestion_control": "bbr2"}, setting: "net.ipv4.tcp_congestion_control"},
	{name: "bbr3: fine", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_congestion_control": "bbr3"}, setting: "net.ipv4.tcp_congestion_control"},

	// forwarding
	{name: "exit pool, forwarding off: fires", cfg: cfgExit, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward", want: "1"},
	{name: "exit pool, forwarding on: fine", cfg: cfgExit, setting: "net.ipv4.ip_forward"},
	{name: "relay pool, forwarding off: not this config's concern", cfg: cfgRelay, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward"},
	{name: "proxy-only exit, forwarding off: not this config's concern", cfg: cfgProxyOnly, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward"},

	{name: "dual-stack exit, v6 forwarding off: fires", cfg: cfgExit, dualStack: true, override: map[string]string{"net.ipv6.conf.all.forwarding": "0"}, setting: "net.ipv6.conf.all.forwarding", want: "1"},
	{name: "dual-stack exit, v6 forwarding on: fine", cfg: cfgExit, dualStack: true, setting: "net.ipv6.conf.all.forwarding"},
	{name: "v4-only exit, v6 forwarding off: silent", cfg: cfgExit, override: map[string]string{"net.ipv6.conf.all.forwarding": "0"}, setting: "net.ipv6.conf.all.forwarding"},

	// conntrack
	{name: "exit /24, conntrack 8192: fires at 253x256", cfg: cfgExit, override: map[string]string{"net.netfilter.nf_conntrack_max": "8192"}, setting: "net.netfilter.nf_conntrack_max", want: "64768",
		wantIn: []string{"up to 253 TUN clients", "net.netfilter.nf_conntrack_buckets=64768", "'nf_conntrack' to /etc/modules-load.d/tiredvpn.conf", "'options nf_conntrack hashsize=64768'"}},
	{name: "exit /24, conntrack 65536: fine", cfg: cfgExit, override: map[string]string{"net.netfilter.nf_conntrack_max": "65536"}, setting: "net.netfilter.nf_conntrack_max"},
	{name: "exit /24 with -max-conns 1: QUIC is not admitted, the pool still counts", cfg: &Config{IPPoolNetwork: "10.8.0.0/24", MaxConcurrentConns: 1}, nofile: 524287, override: map[string]string{"net.netfilter.nf_conntrack_max": "8192", "net.core.somaxconn": "4096"}, setting: "net.netfilter.nf_conntrack_max", want: "64768"},
	{name: "exit /16, 2 GB: the ceiling binds", cfg: cfgExitWide, override: map[string]string{"net.netfilter.nf_conntrack_max": "65536"}, setting: "net.netfilter.nf_conntrack_max", want: "262144"},
	{name: "exit /16, 960 MB: host RAM binds", cfg: cfgExitWide, ram: stockRAM1, override: map[string]string{"net.netfilter.nf_conntrack_max": "65536"}, setting: "net.netfilter.nf_conntrack_max", want: "196655"},
	{name: "relay, conntrack 8192: not this config's concern", cfg: cfgRelay, override: map[string]string{"net.netfilter.nf_conntrack_max": "8192"}, setting: "net.netfilter.nf_conntrack_max"},

	// somaxconn
	{name: "exit, somaxconn 128: fires at 4096", cfg: cfgExit, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn", want: "4096", wantIn: []string{"sysctl -w net.core.somaxconn=4096, then restart the server"}},
	{name: "relay, somaxconn 256 covers admission 256: fine", cfg: cfgRelay, override: map[string]string{"net.core.somaxconn": "256"}, setting: "net.core.somaxconn"},
	{name: "relay, somaxconn 128: fires at 256", cfg: cfgRelay, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn", want: "256"},
	{name: "explicit -max-conns 100, somaxconn 128: fine", cfg: &Config{MaxConcurrentConns: 100}, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn"},
	{name: "-max-conns 10000, somaxconn 4096: capped, fine", cfg: &Config{MaxConcurrentConns: 10000}, nofile: 65536, setting: "net.core.somaxconn"},

	// RLIMIT_NOFILE
	{name: "exit, nofile 1024: fires at 4096x4+1024", cfg: cfgExit, nofile: 1024, setting: "RLIMIT_NOFILE", want: "17408", wantIn: []string{"LimitNOFILE=17408", "--ulimit nofile=17408:17408", "estimated 4 descriptors per connection"}},
	{name: "exit, packaged 65536: fine", cfg: cfgExit, nofile: 65536, setting: "RLIMIT_NOFILE"},
	{name: "relay, nofile exactly 256x4+1024: fine", cfg: cfgRelay, nofile: 2048, setting: "RLIMIT_NOFILE"},
	{name: "relay, nofile 1024: fires at 2048", cfg: cfgRelay, nofile: 1024, setting: "RLIMIT_NOFILE", want: "2048"},
	{name: "absurd -max-conns saturates instead of overflowing", cfg: &Config{MaxConcurrentConns: math.MaxInt}, setting: "RLIMIT_NOFILE", want: "4398046512128"},
}

// run returns what is wrong with the advisor's verdict for tc, nil when it is
// as expected.
func (tc hostTuningCase) run() []string {
	h := tunedHost(tc.override)
	if tc.nofile != 0 {
		h.nofile = tc.nofile
	}
	if tc.ram != 0 {
		h.ram = tc.ram
	}
	h.limit = tc.limit
	rep := adviseHostTuning(hostTuningInputFor(tc.cfg, tc.dualStack), h)
	if len(rep.skipped) != 0 {
		return []string{fmt.Sprintf("unexpected unreadable settings: %v", rep.skipped)}
	}
	got, info := adviceFor(rep, tc.setting)
	if tc.want == "" {
		if got != "" {
			return []string{"rule fired, want silence:\n" + got}
		}
		return nil
	}
	if got == "" {
		return []string{"rule did not fire; lines:\n" + strings.Join(append(rep.info, rep.debug...), "\n")}
	}
	var errs []string
	if wantInfo := ruleBasis(tc.setting) != basisEstimate; info != wantInfo {
		errs = append(errs, fmt.Sprintf("logged at INFO=%v, want INFO=%v (basis %s):\n%s", info, wantInfo, ruleBasis(tc.setting), got))
	}
	if unmeasured := strings.HasPrefix(got, "Host tuning (unmeasured): "); unmeasured != (ruleBasis(tc.setting) == basisEstimate) {
		errs = append(errs, "(unmeasured) tag does not match the rule's basis:\n"+got)
	}
	for _, s := range append([]string{"recommended " + tc.want + " - "}, tc.wantIn...) {
		if !strings.Contains(got, s) {
			errs = append(errs, fmt.Sprintf("line lacks %q:\n%s", s, got))
		}
	}
	for _, s := range tc.wantOut {
		if strings.Contains(got, s) {
			errs = append(errs, fmt.Sprintf("line has %q:\n%s", s, got))
		}
	}
	// Only the rule under test may fire on an otherwise tuned host.
	if n := shortfallCount(rep); n != 1 {
		errs = append(errs, fmt.Sprintf("%d advice lines, want 1:\n%s", n, strings.Join(append(rep.info, rep.debug...), "\n")))
	}
	return errs
}

// shortfallCount counts advice lines, leaving out the summary and the debug
// "ok" lines.
func shortfallCount(rep hostTuningReport) int {
	n := len(rep.info) - 1
	for _, l := range rep.debug {
		if strings.HasPrefix(l, "Host tuning (unmeasured): ") {
			n++
		}
	}
	return n
}

func TestHostTuningRules(t *testing.T) {
	for _, tc := range hostTuningCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range tc.run() {
				t.Error(e)
			}
		})
	}
}

// TestHostTuningRuleMutants breaks each rule in turn and requires the case
// table to notice: a rule that never speaks, one that always speaks, and, for
// rules gated on the config, one that ignores the gate. A rule whose mutant
// passes the table has no case pinning it.
func TestHostTuningRuleMutants(t *testing.T) {
	type checkFn = func(hostTuningInput, hostReader) (*tuningAdvice, string, bool, error)
	fabricated := func(r hostTuningRule) *tuningAdvice {
		return &tuningAdvice{setting: r.setting, current: "mutant", want: "mutant", reason: "mutant", fix: "mutant"}
	}
	mutants := []struct {
		name  string
		gated bool // only meaningful for rules that do not always apply
		wrap  func(r hostTuningRule) checkFn
	}{
		{name: "never fires", wrap: func(r hostTuningRule) checkFn {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
				_, cur, applies, err := r.check(in, h)
				return nil, cur, applies, err
			}
		}},
		{name: "always fires", wrap: func(r hostTuningRule) checkFn {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
				adv, cur, applies, err := r.check(in, h)
				if applies && err == nil && adv == nil {
					adv = fabricated(r)
				}
				return adv, cur, applies, err
			}
		}},
		{name: "ignores the config gate", gated: true, wrap: func(r hostTuningRule) checkFn {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
				adv, cur, applies, err := r.check(in, h)
				if !applies {
					return fabricated(r), "mutant", true, nil
				}
				return adv, cur, applies, err
			}
		}},
	}
	for i, r := range hostTuningRules {
		for _, m := range mutants {
			if m.gated && strings.HasPrefix(r.when, "always") {
				continue
			}
			t.Run(r.setting+"/"+m.name, func(t *testing.T) {
				hostTuningRules[i].check = m.wrap(r)
				defer func() { hostTuningRules[i].check = r.check }()
				killed := 0
				for _, tc := range hostTuningCases {
					if tc.run() != nil {
						killed++
					}
				}
				if killed == 0 {
					t.Fatalf("mutant survived all %d cases", len(hostTuningCases))
				}
			})
		}
	}
}

func TestHostTuningSummary(t *testing.T) {
	const keep = "the server changes none of them itself"
	const keepNAT = keep + " apart from enabling forwarding in the NAT bootstrap"
	last := func(rep hostTuningReport) string { return rep.info[len(rep.info)-1] }
	t.Run("tuned exit: one summary line, nothing to adjust", func(t *testing.T) {
		rep := adviseHostTuning(hostTuningInputFor(cfgExit, true), tunedHost(nil))
		if len(rep.info) != 1 {
			t.Fatalf("got %d info lines, want only the summary:\n%s", len(rep.info), strings.Join(rep.info, "\n"))
		}
		if want := "Host tuning: 6 settings checked for this config, all fine; " + keepNAT; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("tuned relay: no NAT rules, no forwarding clause", func(t *testing.T) {
		rep := adviseHostTuning(hostTuningInputFor(cfgRelay, false), tunedHost(nil))
		if want := "Host tuning: 5 settings checked for this config, all fine; " + keep; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("stock Ubuntu relay: measured at INFO, the estimate at DEBUG", func(t *testing.T) {
		h := tunedHost(map[string]string{
			"net.core.rmem_max":                         "212992",
			"net.core.wmem_max":                         "212992",
			"net.ipv4.tcp_congestion_control":           "cubic",
			"net.ipv4.tcp_available_congestion_control": "reno cubic",
		})
		rep := adviseHostTuning(hostTuningInputFor(cfgRelay, false), h)
		if len(rep.info) != 3 {
			t.Fatalf("got %d info lines, want 2 advice + summary:\n%s", len(rep.info), strings.Join(rep.info, "\n"))
		}
		if want := "Host tuning: 5 settings checked for this config, 2 to adjust, 1 more unmeasured at debug level; " + keep; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("only an estimate short: not all fine", func(t *testing.T) {
		rep := adviseHostTuning(hostTuningInputFor(cfgRelay, false), tunedHost(map[string]string{"net.core.somaxconn": "128"}))
		if want := "Host tuning: 5 settings checked for this config, 0 to adjust, 1 more unmeasured at debug level; " + keep; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("one unreadable among many is counted, never guessed", func(t *testing.T) {
		rep := adviseHostTuning(hostTuningInputFor(cfgExit, false), tunedHost(map[string]string{"net.netfilter.nf_conntrack_max": "<missing>"}))
		if len(rep.skipped) != 1 || !strings.HasPrefix(rep.skipped[0], "net.netfilter.nf_conntrack_max: ") {
			t.Fatalf("skipped = %v", rep.skipped)
		}
		if want := "Host tuning: 4 settings checked for this config, all fine, 1 unreadable; " + keepNAT; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("as many unreadable as checked: inconclusive, not all fine", func(t *testing.T) {
		h := fakeHost{nofile: 524287, ram: stockRAM2, sysctls: map[string]string{
			"net.ipv4.tcp_congestion_control": "bbr", "net.core.somaxconn": "4096",
		}}
		// exit: ip_forward, conntrack unreadable; bbr, somaxconn, nofile readable.
		rep := adviseHostTuning(hostTuningInputFor(cfgExit, false), h)
		if want := "Host tuning: 3 settings checked for this config, all fine, 2 unreadable; " + keepNAT; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
		h.sysctls = map[string]string{"net.core.somaxconn": "4096"}
		rep = adviseHostTuning(hostTuningInputFor(cfgExit, false), h)
		if want := "Host tuning: inconclusive, 3 of 5 settings for this config could not be read (see -debug); " + keepNAT; last(rep) != want {
			t.Fatalf("summary = %q, want %q", last(rep), want)
		}
	})
	t.Run("empty /proc: inconclusive", func(t *testing.T) {
		rep := adviseHostTuning(hostTuningInputFor(cfgExit, false), fakeHost{nofile: 524287, ram: stockRAM2})
		if !strings.HasPrefix(last(rep), "Host tuning: inconclusive, 4 of 5 settings") {
			t.Fatalf("summary = %q", last(rep))
		}
	})
	t.Run("unreadable memory limit skips the relay buffer rules", func(t *testing.T) {
		h := tunedHost(map[string]string{"net.core.rmem_max": "212992"})
		h.limitErr = os.ErrNotExist
		rep := adviseHostTuning(hostTuningInputFor(cfgRelay, false), h)
		if got, _ := adviceFor(rep, "net.core.rmem_max"); got != "" || len(rep.skipped) != 1 {
			t.Fatalf("advice %q, skipped %v; want no advice and one skip", got, rep.skipped)
		}
	})
}

// TestHostTuningLinesCarryNoAddresses checks every line a stock host can
// produce for each config: no IP addresses, no upstream host name.
func TestHostTuningLinesCarryNoAddresses(t *testing.T) {
	stock := fakeHost{nofile: 1024, ram: stockRAM1, limit: 100 << 20, sysctls: map[string]string{
		"net.core.rmem_max":                         "212992",
		"net.core.wmem_max":                         "212992",
		"net.ipv4.tcp_mem":                          "10167 13557 20334",
		"net.ipv4.tcp_congestion_control":           "cubic",
		"net.ipv4.tcp_available_congestion_control": "reno cubic",
		"net.ipv4.ip_forward":                       "0",
		"net.ipv6.conf.all.forwarding":              "0",
		"net.netfilter.nf_conntrack_max":            "8192",
		"net.core.somaxconn":                        "128",
	}}
	ip := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|[0-9a-f]{1,4}::`)
	for _, c := range []*Config{cfgExit, cfgExitQUIC, cfgRelay, cfgRelayBig} {
		rep := adviseHostTuning(hostTuningInputFor(c, true), stock)
		lines := append(rep.info, rep.debug...)
		if shortfallCount(rep) < 4 {
			t.Fatalf("stock host produced only %d advice lines:\n%s", shortfallCount(rep), strings.Join(lines, "\n"))
		}
		for _, l := range lines {
			if ip.MatchString(l) || strings.Contains(l, "exit.invalid") {
				t.Errorf("line carries an address: %s", l)
			}
		}
	}
}

func TestHostTuningInputFor(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		dual bool
		want hostTuningInput
	}{
		{"exit with pool", cfgExit, true, hostTuningInput{natV4: true, natV6: true, poolClients: 253, admissionLimit: 4096}},
		{"exit without dual-stack pool", cfgExit, false, hostTuningInput{natV4: true, poolClients: 253, admissionLimit: 4096}},
		{"proxy-only exit", cfgProxyOnly, true, hostTuningInput{admissionLimit: 4096}},
		{"relay", cfgRelay, true, hostTuningInput{upstream: true, upstreamBuf: 512 * 1024, admissionLimit: 256}},
		{"relay with -relay-upstream-buf", cfgRelayBig, false, hostTuningInput{upstream: true, upstreamBuf: 2 << 20, admissionLimit: 256}},
		{"explicit -max-conns", &Config{MaxConcurrentConns: 100, UpstreamAddr: "exit.invalid:443"}, false, hostTuningInput{upstream: true, upstreamBuf: 512 * 1024, admissionLimit: 100}},
	}
	for _, tc := range cases {
		if got := hostTuningInputFor(tc.cfg, tc.dual); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPoolDualStack(t *testing.T) {
	if poolDualStack(nil) || poolDualStack(&serverContext{}) {
		t.Fatal("no pool reads as dual-stack")
	}
	for _, v6 := range []string{"", "fd00:77::/64"} {
		pool, err := NewIPPool(IPPoolConfig{Network: "10.77.0.0/24", ServerIP: "10.77.0.1", NetworkV6: v6}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := poolDualStack(&serverContext{ipPool: pool}); got != (v6 != "") {
			t.Errorf("pool v6 %q: dual-stack %v", v6, got)
		}
	}
}

func TestCgroupMemLimit(t *testing.T) {
	files := map[string]string{
		"/sys/fs/cgroup/system.slice/memory.max":                             "max\n",
		"/sys/fs/cgroup/system.slice/tiredvpn-server.service/memory.max":     "104857600\n",
		"/sys/fs/cgroup/limited.slice/memory.max":                            "52428800\n",
		"/sys/fs/cgroup/limited.slice/a.service/memory.max":                  "max\n",
		"/sys/fs/cgroup/free.slice/b.service/memory.max":                     "max\n",
		"/sys/fs/cgroup/memory/system.slice/c.service/memory.limit_in_bytes": "209715200\n",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes":                        "9223372036854771712\n",
		"/sys/fs/cgroup/bad.slice/d.service/memory.max":                      "lots\n",
	}
	read := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	cases := []struct {
		self    string
		limit   uint64
		limited bool
		err     bool
	}{
		{"0::/system.slice/tiredvpn-server.service\n", 100 << 20, true, false},
		{"0::/limited.slice/a.service\n", 50 << 20, true, false}, // the parent's limit binds
		{"0::/free.slice/b.service\n", 0, false, false},
		{"0::/\n", 0, false, false},
		{"12:memory:/system.slice/c.service\n1:name=systemd:/x\n0::/x\n", 200 << 20, true, false},
		{"0::/bad.slice/d.service\n", 0, false, true},
		{"1:name=systemd:/x\n", 0, false, true},
	}
	for _, tc := range cases {
		limit, limited, err := cgroupMemLimit(tc.self, read)
		if (err != nil) != tc.err || limit != tc.limit || limited != tc.limited {
			t.Errorf("%q: got %d %v %v, want %d %v err=%v", tc.self, limit, limited, err, tc.limit, tc.limited, tc.err)
		}
	}
}

func TestParseMemTotal(t *testing.T) {
	got, err := parseMemTotal("MemTotal:         983276 kB\nMemFree:  114 kB\n")
	if err != nil || got != 983276*1024 {
		t.Fatalf("got %d, %v", got, err)
	}
	for _, bad := range []string{"", "MemTotal: 12\n", "MemTotal: x kB\n"} {
		if _, err := parseMemTotal(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestPoolHostCount(t *testing.T) {
	for cidr, want := range map[string]int{
		"10.8.0.0/24": 253, "10.8.0.0/30": 1, "10.8.0.0/31": 0, "10.8.0.0/16": 65533,
		"10.0.0.0/8": 1<<20 - 3, "fd00::/64": 0, "garbage": 0,
	} {
		if got := poolHostCount(cidr); got != want {
			t.Errorf("poolHostCount(%q) = %d, want %d", cidr, got, want)
		}
	}
}

const (
	hostTuningDocBegin = "<!-- host-tuning-table:begin (generated from internal/server/host_tuning.go; go test ./internal/server -run TestHostTuningDocsInSync -update-host-tuning-docs) -->\n"
	hostTuningDocEnd   = "<!-- host-tuning-table:end -->"
)

// TestHostTuningDocsInSync keeps the docs table identical to the rule table.
func TestHostTuningDocsInSync(t *testing.T) {
	const path = "../../docs/server.md"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	before, rest, ok := strings.Cut(doc, hostTuningDocBegin)
	if !ok {
		t.Fatalf("%s lacks the begin marker %q", path, hostTuningDocBegin)
	}
	current, after, ok := strings.Cut(rest, hostTuningDocEnd)
	if !ok {
		t.Fatalf("%s lacks the end marker %q", path, hostTuningDocEnd)
	}
	want := hostTuningDocTable()
	if current == want {
		return
	}
	if *updateHostTuningDocs {
		if err := os.WriteFile(path, []byte(before+hostTuningDocBegin+want+hostTuningDocEnd+after), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("docs/server.md Host tuning table is out of date; run: go test ./internal/server -run TestHostTuningDocsInSync -update-host-tuning-docs\n--- docs\n%s--- code\n%s", current, want)
}

// TestHostTuningConntrackFollowsNAT pins the NAT gate on its own:
// hostTuningInputFor leaves poolClients at zero without NAT, which would hide
// a missing gate.
func TestHostTuningConntrackFollowsNAT(t *testing.T) {
	h := tunedHost(map[string]string{"net.netfilter.nf_conntrack_max": "8192"})
	in := hostTuningInput{poolClients: 253, admissionLimit: 4096}
	if adv, _, applies, _ := conntrackRule(in, h); applies || adv != nil {
		t.Fatalf("no NAT: applies=%v advice=%v", applies, adv)
	}
	in.natV4 = true
	if adv, _, applies, _ := conntrackRule(in, h); !applies || adv == nil || adv.want != "64768" {
		t.Fatalf("NAT: applies=%v advice=%+v", applies, adv)
	}
}
