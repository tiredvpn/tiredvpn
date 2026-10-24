package server

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

var updateHostTuningDocs = flag.Bool("update-host-tuning-docs", false, "rewrite the Host tuning table in docs/server.md from hostTuningRules")

// fakeHost is a host whose sysctls are a map. A missing key reads as a missing
// /proc file.
type fakeHost struct {
	sysctls map[string]string
	nofile  uint64
}

func (f fakeHost) sysctl(name string) (string, error) {
	v, ok := f.sysctls[name]
	if !ok {
		return "", fmt.Errorf("open /proc/sys/%s: %w", strings.ReplaceAll(name, ".", "/"), os.ErrNotExist)
	}
	return v, nil
}

func (f fakeHost) nofileSoft() (uint64, error) { return f.nofile, nil }

// tunedHost satisfies every rule for every config used below.
func tunedHost(override map[string]string) fakeHost {
	h := fakeHost{nofile: 524287, sysctls: map[string]string{
		"net.core.rmem_max":                         "16777216",
		"net.core.wmem_max":                         "16777216",
		"net.ipv4.tcp_rmem":                         "4096 87380 16777216",
		"net.ipv4.tcp_wmem":                         "4096 65536 16777216",
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

// adviceFor returns the advice line for setting, or "" when it did not fire.
func adviceFor(lines []string, setting string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, "Host tuning: "+setting+" is ") {
			return l
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
	// rmem_max follows the buffer this config requests.
	{name: "relay default buf, rmem 1MiB: fine", cfg: cfgRelay, override: map[string]string{"net.core.rmem_max": "1048576"}, setting: "net.core.rmem_max"},
	{name: "relay default buf, stock rmem: fires at 512K", cfg: cfgRelay, override: map[string]string{"net.core.rmem_max": "212992"}, setting: "net.core.rmem_max", want: "524288",
		wantIn: []string{"is 212992", "upstream dialer requests 524288-byte", "sysctl -w net.core.rmem_max=524288", "'net.core.rmem_max = 524288' to /etc/sysctl.d/90-tiredvpn.conf"}},
	{name: "relay -relay-upstream-buf 2MiB, rmem 1MiB: fires at 2MiB", cfg: cfgRelayBig, override: map[string]string{"net.core.rmem_max": "1048576"}, setting: "net.core.rmem_max", want: "2097152"},
	{name: "exit, rmem 1MiB: fires at 4MiB for target dials", cfg: cfgExit, override: map[string]string{"net.core.rmem_max": "1048576"}, setting: "net.core.rmem_max", want: "4194304", wantIn: []string{"direct target dials"}},
	{name: "exit, rmem exactly 4MiB: fine", cfg: cfgExit, override: map[string]string{"net.core.rmem_max": "4194304"}, setting: "net.core.rmem_max"},
	{name: "exit with QUIC, rmem 4MiB: fires at 7.5MB", cfg: cfgExitQUIC, override: map[string]string{"net.core.rmem_max": "4194304"}, setting: "net.core.rmem_max", want: "7500000", wantIn: []string{"QUIC"}},

	{name: "relay, stock wmem: fires", cfg: cfgRelay, override: map[string]string{"net.core.wmem_max": "212992"}, setting: "net.core.wmem_max", want: "524288"},
	{name: "relay, wmem exactly 512K: fine", cfg: cfgRelay, override: map[string]string{"net.core.wmem_max": "524288"}, setting: "net.core.wmem_max"},
	{name: "exit, wmem 1MiB: fires at 4MiB", cfg: cfgExit, override: map[string]string{"net.core.wmem_max": "1048576"}, setting: "net.core.wmem_max", want: "4194304"},

	{name: "tcp_rmem max 2MiB: fires, keeps min and default", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_rmem": "4096 131072 2097152"}, setting: "net.ipv4.tcp_rmem", want: "4096 131072 4194304",
		wantIn: []string{`sysctl -w net.ipv4.tcp_rmem="4096 131072 4194304"`, "'net.ipv4.tcp_rmem = 4096 131072 4194304'"}},
	{name: "tcp_rmem stock: fine", cfg: cfgRelay, override: map[string]string{"net.ipv4.tcp_rmem": "4096 131072 6291456"}, setting: "net.ipv4.tcp_rmem"},
	{name: "tcp_wmem max 1MiB: fires", cfg: cfgRelay, override: map[string]string{"net.ipv4.tcp_wmem": "4096 16384 1048576"}, setting: "net.ipv4.tcp_wmem", want: "4096 16384 4194304"},
	{name: "tcp_wmem exactly 4MiB: fine", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_wmem": "4096 16384 4194304"}, setting: "net.ipv4.tcp_wmem"},

	{name: "cubic, bbr not loaded: fires with modprobe", cfg: cfgExit, override: map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.ipv4.tcp_available_congestion_control": "reno cubic"}, setting: "net.ipv4.tcp_congestion_control", want: "bbr",
		wantIn: []string{"modprobe tcp_bbr && sysctl -w net.ipv4.tcp_congestion_control=bbr", "/etc/modules-load.d/tiredvpn.conf"}},
	{name: "cubic, bbr available: fires without modprobe", cfg: cfgRelay, override: map[string]string{"net.ipv4.tcp_congestion_control": "cubic"}, setting: "net.ipv4.tcp_congestion_control", want: "bbr",
		wantIn: []string{"Fix: sysctl -w net.ipv4.tcp_congestion_control=bbr"}, wantOut: []string{"modprobe"}},
	{name: "bbr: fine", cfg: cfgExit, setting: "net.ipv4.tcp_congestion_control"},

	{name: "exit pool, forwarding off: fires", cfg: cfgExit, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward", want: "1"},
	{name: "exit pool, forwarding on: fine", cfg: cfgExit, setting: "net.ipv4.ip_forward"},
	{name: "relay pool, forwarding off: not this config's concern", cfg: cfgRelay, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward"},
	{name: "proxy-only exit, forwarding off: not this config's concern", cfg: cfgProxyOnly, override: map[string]string{"net.ipv4.ip_forward": "0"}, setting: "net.ipv4.ip_forward"},

	{name: "dual-stack exit, v6 forwarding off: fires", cfg: cfgExit, dualStack: true, override: map[string]string{"net.ipv6.conf.all.forwarding": "0"}, setting: "net.ipv6.conf.all.forwarding", want: "1"},
	{name: "dual-stack exit, v6 forwarding on: fine", cfg: cfgExit, dualStack: true, setting: "net.ipv6.conf.all.forwarding"},
	{name: "v4-only exit, v6 forwarding off: silent", cfg: cfgExit, override: map[string]string{"net.ipv6.conf.all.forwarding": "0"}, setting: "net.ipv6.conf.all.forwarding"},

	{name: "exit /24, conntrack 8192: fires at 253x256", cfg: cfgExit, override: map[string]string{"net.netfilter.nf_conntrack_max": "8192"}, setting: "net.netfilter.nf_conntrack_max", want: "64768", wantIn: []string{"253 TUN clients"}},
	{name: "exit /24, conntrack 65536: fine", cfg: cfgExit, override: map[string]string{"net.netfilter.nf_conntrack_max": "65536"}, setting: "net.netfilter.nf_conntrack_max"},
	{name: "exit /16, admission 4096 bounds the clients, ceiling bounds the rest", cfg: cfgExitWide, override: map[string]string{"net.netfilter.nf_conntrack_max": "65536"}, setting: "net.netfilter.nf_conntrack_max", want: "262144", wantIn: []string{"4096 TUN clients"}},
	{name: "relay, conntrack 8192: not this config's concern", cfg: cfgRelay, override: map[string]string{"net.netfilter.nf_conntrack_max": "8192"}, setting: "net.netfilter.nf_conntrack_max"},

	{name: "exit, somaxconn 128: fires at 4096", cfg: cfgExit, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn", want: "4096"},
	{name: "relay, somaxconn 256 covers admission 256: fine", cfg: cfgRelay, override: map[string]string{"net.core.somaxconn": "256"}, setting: "net.core.somaxconn"},
	{name: "relay, somaxconn 128: fires at 256", cfg: cfgRelay, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn", want: "256"},
	{name: "-max-conns 10000, somaxconn 4096: capped, fine", cfg: &Config{MaxConcurrentConns: 10000}, nofile: 65536, setting: "net.core.somaxconn"},
	{name: "explicit -max-conns 100, somaxconn 128: fine", cfg: &Config{MaxConcurrentConns: 100}, override: map[string]string{"net.core.somaxconn": "128"}, setting: "net.core.somaxconn"},

	{name: "exit, nofile 1024: fires at 4096x4+1024", cfg: cfgExit, nofile: 1024, setting: "RLIMIT_NOFILE", want: "17408", wantIn: []string{"LimitNOFILE=17408", "--ulimit nofile=17408:17408"}},
	{name: "exit, packaged 65536: fine", cfg: cfgExit, nofile: 65536, setting: "RLIMIT_NOFILE"},
	{name: "relay, nofile exactly 256x4+1024: fine", cfg: cfgRelay, nofile: 2048, setting: "RLIMIT_NOFILE"},
	{name: "relay, nofile 1024: fires at 2048", cfg: cfgRelay, nofile: 1024, setting: "RLIMIT_NOFILE", want: "2048"},
}

// run returns what is wrong with the advisor's verdict for tc, nil when it is
// as expected.
func (tc hostTuningCase) run() []string {
	h := tunedHost(tc.override)
	if tc.nofile != 0 {
		h.nofile = tc.nofile
	}
	lines, skipped := adviseHostTuning(hostTuningInputFor(tc.cfg, tc.dualStack), h)
	if len(skipped) != 0 {
		return []string{fmt.Sprintf("unexpected unreadable settings: %v", skipped)}
	}
	got := adviceFor(lines, tc.setting)
	if tc.want == "" {
		if got != "" {
			return []string{"rule fired, want silence:\n" + got}
		}
		return nil
	}
	if got == "" {
		return []string{"rule did not fire; lines:\n" + strings.Join(lines, "\n")}
	}
	var errs []string
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
	if n := len(lines) - 1; n != 1 {
		errs = append(errs, fmt.Sprintf("%d advice lines, want 1:\n%s", n, strings.Join(lines, "\n")))
	}
	return errs
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
	fabricated := func(r hostTuningRule) *tuningAdvice {
		return &tuningAdvice{setting: r.setting, current: "mutant", want: "mutant", reason: "mutant", fix: "mutant"}
	}
	mutants := []struct {
		name  string
		gated bool // only meaningful for rules that do not always apply
		wrap  func(r hostTuningRule) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error)
	}{
		{name: "never fires", wrap: func(r hostTuningRule) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
				_, applies, err := r.check(in, h)
				return nil, applies, err
			}
		}},
		{name: "always fires", wrap: func(r hostTuningRule) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
				adv, applies, err := r.check(in, h)
				if applies && err == nil && adv == nil {
					adv = fabricated(r)
				}
				return adv, applies, err
			}
		}},
		{name: "ignores the config gate", gated: true, wrap: func(r hostTuningRule) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
			return func(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
				adv, applies, err := r.check(in, h)
				if !applies {
					return fabricated(r), true, nil
				}
				return adv, applies, err
			}
		}},
	}
	for i, r := range hostTuningRules {
		for _, m := range mutants {
			if m.gated && r.when == "always" {
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
	t.Run("tuned exit: one summary line, nothing to adjust", func(t *testing.T) {
		lines, _ := adviseHostTuning(hostTuningInputFor(cfgExit, true), tunedHost(nil))
		if len(lines) != 1 {
			t.Fatalf("got %d lines, want only the summary:\n%s", len(lines), strings.Join(lines, "\n"))
		}
		want := "Host tuning: 10 settings checked for this config, all fine; the server changes none of them itself"
		if lines[0] != want {
			t.Fatalf("summary = %q, want %q", lines[0], want)
		}
	})
	t.Run("relay skips the NAT rules", func(t *testing.T) {
		lines, _ := adviseHostTuning(hostTuningInputFor(cfgRelay, false), tunedHost(nil))
		if want := "Host tuning: 7 settings checked for this config, all fine; the server changes none of them itself"; lines[0] != want {
			t.Fatalf("summary = %q, want %q", lines[0], want)
		}
	})
	t.Run("stock Ubuntu relay: the shortfalls and a count", func(t *testing.T) {
		h := tunedHost(map[string]string{
			"net.core.rmem_max":                         "212992",
			"net.core.wmem_max":                         "212992",
			"net.ipv4.tcp_congestion_control":           "cubic",
			"net.ipv4.tcp_available_congestion_control": "reno cubic",
		})
		lines, _ := adviseHostTuning(hostTuningInputFor(cfgRelay, false), h)
		if len(lines) != 4 {
			t.Fatalf("got %d lines, want 3 advice + summary:\n%s", len(lines), strings.Join(lines, "\n"))
		}
		if want := "Host tuning: 7 settings checked for this config, 3 to adjust; the server changes none of them itself"; lines[3] != want {
			t.Fatalf("summary = %q, want %q", lines[3], want)
		}
	})
	t.Run("unreadable conntrack is skipped and counted, never guessed", func(t *testing.T) {
		lines, skipped := adviseHostTuning(hostTuningInputFor(cfgExit, false), tunedHost(map[string]string{"net.netfilter.nf_conntrack_max": "<missing>"}))
		if len(skipped) != 1 || !strings.HasPrefix(skipped[0], "net.netfilter.nf_conntrack_max: ") {
			t.Fatalf("skipped = %v", skipped)
		}
		if want := "Host tuning: 8 settings checked for this config, all fine, 1 unreadable; the server changes none of them itself"; lines[len(lines)-1] != want {
			t.Fatalf("summary = %q, want %q", lines[len(lines)-1], want)
		}
	})
}

// TestHostTuningLinesCarryNoAddresses checks every advice line a stock host
// can produce for each config: no IP addresses, no upstream host name.
func TestHostTuningLinesCarryNoAddresses(t *testing.T) {
	stock := fakeHost{nofile: 1024, sysctls: map[string]string{
		"net.core.rmem_max":                         "212992",
		"net.core.wmem_max":                         "212992",
		"net.ipv4.tcp_rmem":                         "4096 131072 1048576",
		"net.ipv4.tcp_wmem":                         "4096 16384 1048576",
		"net.ipv4.tcp_congestion_control":           "cubic",
		"net.ipv4.tcp_available_congestion_control": "reno cubic",
		"net.ipv4.ip_forward":                       "0",
		"net.ipv6.conf.all.forwarding":              "0",
		"net.netfilter.nf_conntrack_max":            "8192",
		"net.core.somaxconn":                        "128",
	}}
	ip := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|[0-9a-f]{1,4}::`)
	for _, c := range []*Config{cfgExit, cfgExitQUIC, cfgRelay, cfgRelayBig} {
		lines, _ := adviseHostTuning(hostTuningInputFor(c, true), stock)
		if len(lines) < 5 {
			t.Fatalf("stock host produced only %d lines", len(lines))
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
		{"QUIC", cfgExitQUIC, false, hostTuningInput{quic: true, natV4: true, poolClients: 253, admissionLimit: 4096}},
		{"explicit -max-conns", &Config{MaxConcurrentConns: 100, UpstreamAddr: "exit.invalid:443"}, false, hostTuningInput{upstream: true, upstreamBuf: 512 * 1024, admissionLimit: 100}},
	}
	for _, tc := range cases {
		if got := hostTuningInputFor(tc.cfg, tc.dual); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
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

// TestConntrackNeedFollowsNAT pins the NAT gate on its own: hostTuningInputFor
// leaves poolClients at zero without NAT, which would hide a missing gate.
func TestConntrackNeedFollowsNAT(t *testing.T) {
	in := hostTuningInput{poolClients: 253, admissionLimit: 4096}
	if n, _ := conntrackNeed(in); n != 0 {
		t.Fatalf("no NAT: need %d, want 0", n)
	}
	in.natV4 = true
	if n, _ := conntrackNeed(in); n != 253*conntrackPerClient {
		t.Fatalf("NAT: need %d, want %d", n, 253*conntrackPerClient)
	}
}
