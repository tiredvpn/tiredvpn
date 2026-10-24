package server

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Host tuning advisor.
//
// At startup the server reads the kernel and process settings that decide how
// well it can run, compares each against what this server's own configuration
// asks of the host, and logs one INFO line per setting that falls short, with
// the exact command to fix it. It never writes a setting itself: changing a
// host's kernel is the operator's call.
//
// Every rule is derived from the configuration rather than from a fixed list
// of "good values": the socket-buffer ceiling is checked against the buffer
// this process will actually request, forwarding only when the TUN pool's
// traffic leaves through this host, and so on. The rule table below also
// generates the "Host tuning" section of docs/server.md (see
// TestHostTuningDocsInSync), so the two cannot drift apart.

const (
	// targetDialSockBuf is the SO_RCVBUF/SO_SNDBUF that setTCPOptions requests
	// on every direct target dial of an exit node.
	targetDialSockBuf = 4 * 1024 * 1024

	// quicUDPSockBuf is the UDP buffer quic-go asks for; below it the QUIC
	// listener runs with a clamped receive buffer.
	quicUDPSockBuf = 7500000

	// tcpAutotuneMax is the floor for the third field of tcp_rmem/tcp_wmem, the
	// autotuning ceiling for the client-facing sockets the server accepts
	// without setting a buffer. 4 MiB covers ~64 Mbit/s at 500 ms RTT, the
	// longest relay leg we have measured.
	tcpAutotuneMax = 4 * 1024 * 1024

	// fdsPerConn budgets descriptors per admitted connection: the client
	// socket, its target or upstream leg, and slack for mux sessions that open
	// several targets over one connection. An assumption, not a measurement.
	fdsPerConn = 4

	// fdHeadroom covers listeners, TUN, Redis, log files and the runtime.
	fdHeadroom = 1024

	// conntrackPerClient is the conntrack budget per TUN client behind this
	// host's MASQUERADE. An assumption, not a measurement: no per-client flow
	// count has been taken on our exits.
	conntrackPerClient = 256

	// conntrackCeiling caps the recommendation for very large pools, where the
	// admission limit and memory bind long before the conntrack table does.
	conntrackCeiling = 262144

	// hostTuningSysctlFile is the drop-in the persist hints point at.
	hostTuningSysctlFile = "/etc/sysctl.d/90-tiredvpn.conf"
)

// hostTuningInput is what this server's configuration asks of the host.
type hostTuningInput struct {
	upstream    bool // -upstream: target and TUN traffic goes to the upstream exit
	upstreamBuf int  // socket buffer the upstream dialer requests
	quic        bool
	// natV4 / natV6: a TUN pool whose traffic is forwarded and masqueraded out
	// of this host (an exit with -ip-pool, not a relay bridging to upstream).
	natV4, natV6   bool
	poolClients    int // usable addresses in the v4 pool
	admissionLimit int
}

// hostTuningInputFor derives the input from the effective configuration.
// dualStack is the IP pool's own verdict (NAT66 is set up only then).
func hostTuningInputFor(cfg *Config, dualStack bool) hostTuningInput {
	in := hostTuningInput{
		upstream:       cfg.UpstreamAddr != "",
		quic:           cfg.QUICEnabled,
		admissionLimit: admissionLimitFor(cfg),
	}
	if in.upstream {
		in.upstreamBuf = defaultUpstreamSockBuf
		if cfg.RelayUpstreamBufBytes > 0 {
			in.upstreamBuf = cfg.RelayUpstreamBufBytes
		}
	}
	if cfg.IPPoolNetwork != "" && !in.upstream {
		in.natV4 = true
		in.natV6 = dualStack
		in.poolClients = poolHostCount(cfg.IPPoolNetwork)
	}
	return in
}

// poolHostCount is the number of client addresses in a v4 CIDR: everything
// but the network, broadcast and server addresses.
func poolHostCount(cidr string) int {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return 0
	}
	// Past /12 the conntrack recommendation is at its ceiling anyway; capping
	// here keeps the shift inside a 32-bit int.
	return max((1<<min(bits-ones, 20))-3, 0)
}

// hostReader is the host as the advisor sees it. The production reader is
// /proc/sys plus getrlimit; tests substitute a map.
type hostReader interface {
	// sysctl returns the value of a dotted sysctl name, e.g. net.core.rmem_max.
	sysctl(name string) (string, error)
	// nofileSoft returns the soft RLIMIT_NOFILE the process runs with.
	nofileSoft() (uint64, error)
}

type procHost struct{}

func (procHost) sysctl(name string) (string, error) {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (procHost) nofileSoft() (uint64, error) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, err
	}
	return uint64(rl.Cur), nil
}

// tuningAdvice is one setting that falls short of what the config needs.
type tuningAdvice struct {
	setting string
	current string
	want    string
	reason  string
	fix     string // command that applies it now
	persist string // how to keep it across reboots
}

func (a tuningAdvice) line() string {
	s := fmt.Sprintf("Host tuning: %s is %s, recommended %s - %s. Fix: %s", a.setting, a.current, a.want, a.reason, a.fix)
	if a.persist != "" {
		s += "; persist: " + a.persist
	}
	return s
}

// hostTuningRule is one check. The doc fields feed docs/server.md.
type hostTuningRule struct {
	setting  string
	when     string // when the rule applies
	want     string // recommended value, as documented
	why      string
	evidence string
	// check returns applies=false when the config does not need the setting,
	// a non-nil advice when the host falls short, and an error when the value
	// could not be read (the rule is then skipped, never guessed).
	check func(in hostTuningInput, h hostReader) (adv *tuningAdvice, applies bool, err error)
}

// sockBufNeed is the largest socket buffer this config will request, and why.
func sockBufNeed(in hostTuningInput) (int, string) {
	need, why := targetDialSockBuf, "direct target dials request 4 MiB socket buffers and the kernel silently clamps them to this ceiling"
	if in.upstream {
		need, why = in.upstreamBuf, fmt.Sprintf("the upstream dialer requests %d-byte socket buffers and the kernel silently clamps them to this ceiling", in.upstreamBuf)
	}
	if in.quic && quicUDPSockBuf > need {
		need, why = quicUDPSockBuf, "the QUIC listener asks for 7.5 MB UDP buffers"
	}
	return need, why
}

// sysctlFix renders the runtime command and the sysctl.d line for one value.
// Multi-field values (tcp_rmem) are quoted for the shell.
func sysctlFix(name, value string) (fix, persist string) {
	arg := value
	if strings.ContainsAny(value, " \t") {
		arg = strconv.Quote(value)
	}
	return fmt.Sprintf("sysctl -w %s=%s", name, arg), fmt.Sprintf("add '%s = %s' to %s", name, value, hostTuningSysctlFile)
}

func readInt(h hostReader, name string) (int64, error) {
	v, err := h.sysctl(name)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
}

// minIntRule fires when an integer sysctl is below need(in). need returns 0
// when the config does not use the setting.
func minIntRule(name string, need func(hostTuningInput) (int64, string)) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
	return func(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
		want, reason := need(in)
		if want <= 0 {
			return nil, false, nil
		}
		cur, err := readInt(h, name)
		if err != nil {
			return nil, true, err
		}
		if cur >= want {
			return nil, true, nil
		}
		w := strconv.FormatInt(want, 10)
		fix, persist := sysctlFix(name, w)
		return &tuningAdvice{setting: name, current: strconv.FormatInt(cur, 10), want: w, reason: reason, fix: fix, persist: persist}, true, nil
	}
}

// autotuneMaxRule checks the third field of tcp_rmem / tcp_wmem.
func autotuneMaxRule(name string) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
	return func(_ hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
		v, err := h.sysctl(name)
		if err != nil {
			return nil, true, err
		}
		f := strings.Fields(v)
		if len(f) != 3 {
			return nil, true, fmt.Errorf("%s: want 3 fields, got %q", name, v)
		}
		cur, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, true, err
		}
		if cur >= tcpAutotuneMax {
			return nil, true, nil
		}
		want := fmt.Sprintf("%s %s %d", f[0], f[1], tcpAutotuneMax)
		fix, persist := sysctlFix(name, want)
		return &tuningAdvice{
			setting: name, current: strings.Join(f, " "), want: want,
			reason: "client sockets autotune up to the last field, and a smaller window caps one client's throughput on a long-RTT leg",
			fix:    fix, persist: persist,
		}, true, nil
	}
}

// equalsOneRule fires when a boolean sysctl is not 1 while the config needs it.
func equalsOneRule(name string, needed func(hostTuningInput) bool, reason string) func(hostTuningInput, hostReader) (*tuningAdvice, bool, error) {
	return func(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
		if !needed(in) {
			return nil, false, nil
		}
		v, err := h.sysctl(name)
		if err != nil {
			return nil, true, err
		}
		if v == "1" {
			return nil, true, nil
		}
		fix, persist := sysctlFix(name, "1")
		return &tuningAdvice{setting: name, current: v, want: "1", reason: reason, fix: fix, persist: persist}, true, nil
	}
}

func congestionRule(_ hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
	const name = "net.ipv4.tcp_congestion_control"
	cur, err := h.sysctl(name)
	if err != nil {
		return nil, true, err
	}
	if cur == "bbr" {
		return nil, true, nil
	}
	fix, persist := sysctlFix(name, "bbr")
	if avail, err := h.sysctl("net.ipv4.tcp_available_congestion_control"); err != nil || !slices.Contains(strings.Fields(avail), "bbr") {
		fix = "modprobe tcp_bbr && " + fix
		persist = "add 'tcp_bbr' to /etc/modules-load.d/tiredvpn.conf and '" + name + " = bbr' to " + hostTuningSysctlFile
	}
	return &tuningAdvice{
		setting: name, current: cur, want: "bbr",
		reason: "loss-based congestion control backs off on random loss over long-RTT paths",
		fix:    fix, persist: persist,
	}, true, nil
}

func nofileNeed(in hostTuningInput) uint64 {
	return uint64(in.admissionLimit*fdsPerConn + fdHeadroom)
}

func nofileRule(in hostTuningInput, h hostReader) (*tuningAdvice, bool, error) {
	cur, err := h.nofileSoft()
	if err != nil {
		return nil, true, err
	}
	want := nofileNeed(in)
	if cur >= want {
		return nil, true, nil
	}
	return &tuningAdvice{
		setting: "RLIMIT_NOFILE", current: strconv.FormatUint(cur, 10), want: strconv.FormatUint(want, 10),
		reason: fmt.Sprintf("admission control lets in %d connections and each holds at least two descriptors, so accept fails with EMFILE first", in.admissionLimit),
		fix:    fmt.Sprintf("set LimitNOFILE=%d in the [Service] section of the unit (docker: --ulimit nofile=%d:%d) and restart", want, want, want),
	}, true, nil
}

func conntrackNeed(in hostTuningInput) (int64, string) {
	if !in.natV4 {
		return 0, ""
	}
	clients := min(in.poolClients, in.admissionLimit)
	need := min(clients*conntrackPerClient, conntrackCeiling)
	return int64(need), fmt.Sprintf("every flow of %d TUN clients is masqueraded here at about %d flows each, and a full table drops new flows", clients, conntrackPerClient)
}

func somaxconnNeed(in hostTuningInput) (int64, string) {
	return int64(min(in.admissionLimit, 4096)), fmt.Sprintf("the listen backlog is this value and a reconnect storm arrives faster than admission (%d) can drain it", in.admissionLimit)
}

var hostTuningRules = []hostTuningRule{
	{
		setting:  "net.core.rmem_max",
		when:     "always",
		want:     ">= the largest socket buffer the config requests: 4 MiB on an exit (target dials), `-relay-upstream-buf` or 512 KiB on a relay, 7.5 MB with QUIC",
		why:      "`SO_RCVBUF` above this is clamped without an error, so the receive window of every such socket is capped",
		evidence: "Relay on stock Ubuntu 24.04, 146 ms upstream leg (2026-10-24): 212992 held the leg at `rcv_ssthresh` 210439 and TUN downloads at 6.3-8.7 Mbit/s; 1 MiB gave 19.8-20.1 Mbit/s. Same class as the hard-coded 64 KB buffers that held 1.3.x at ~3.5 Mbit/s on 150 ms. Two of our exits still run 212992 (read 2026-10-24), which clamps their 4 MiB target-dial buffers; the effect on that leg has not been measured",
		check: minIntRule("net.core.rmem_max", func(in hostTuningInput) (int64, string) {
			n, why := sockBufNeed(in)
			return int64(n), why
		}),
	},
	{
		setting:  "net.core.wmem_max",
		when:     "always",
		want:     "same as `net.core.rmem_max`",
		why:      "`SO_SNDBUF` is clamped the same way, capping how much one socket keeps in flight",
		evidence: "Raised together with `rmem_max` in the relay measurement above; of the seven nodes read on 2026-10-24 one runs 16 MiB for both, two 4 MiB, one 1 MiB, two exits the stock 212992",
		check: minIntRule("net.core.wmem_max", func(in hostTuningInput) (int64, string) {
			n, why := sockBufNeed(in)
			return int64(n), why
		}),
	},
	{
		setting:  "net.ipv4.tcp_rmem",
		when:     "always",
		want:     "last field >= 4 MiB",
		why:      "accepted client sockets set no buffer and autotune up to the last field",
		evidence: "Not seen as a bottleneck: stock Ubuntu 24.04 has 6291456, our tuned exit 16777216. The rule only catches a host tuned below that",
		check:    autotuneMaxRule("net.ipv4.tcp_rmem"),
	},
	{
		setting:  "net.ipv4.tcp_wmem",
		when:     "always",
		want:     "last field >= 4 MiB",
		why:      "same as `tcp_rmem`, for the send side of client sockets",
		evidence: "Not seen as a bottleneck: stock Ubuntu 24.04 has 4194304, our tuned exit 16777216",
		check:    autotuneMaxRule("net.ipv4.tcp_wmem"),
	},
	{
		setting:  "net.ipv4.tcp_congestion_control",
		when:     "always",
		want:     "`bbr`",
		why:      "loss-based cubic backs off on random loss over long-RTT paths",
		evidence: "One of the seven nodes read on 2026-10-24 runs bbr, six run cubic. No A/B throughput measurement has been made, so treat it as a default, not a measured gain",
		check:    congestionRule,
	},
	{
		setting:  "net.ipv4.ip_forward",
		when:     "`-ip-pool` on an exit (no `-upstream`)",
		want:     "1",
		why:      "TUN clients' packets are forwarded out of this host; the server sets it at startup, so 0 here means its own attempt failed",
		evidence: "Set by the NAT bootstrap (internal/tun/nat_linux.go); the advisor runs after it and only reports",
		check: equalsOneRule("net.ipv4.ip_forward", func(in hostTuningInput) bool { return in.natV4 },
			"TUN clients' packets are forwarded out of this host and the server's own attempt to enable it failed"),
	},
	{
		setting:  "net.ipv6.conf.all.forwarding",
		when:     "`-ip-pool` with `-ip-pool-v6` on an exit",
		want:     "1",
		why:      "same as `ip_forward`, for the dual-stack pool",
		evidence: "Set by the NAT66 bootstrap; without it v6 inside the tunnel is blackholed",
		check: equalsOneRule("net.ipv6.conf.all.forwarding", func(in hostTuningInput) bool { return in.natV6 },
			"dual-stack TUN clients' IPv6 is forwarded out of this host and the server's own attempt to enable it failed"),
	},
	{
		setting:  "net.netfilter.nf_conntrack_max",
		when:     "`-ip-pool` on an exit (skipped while nf_conntrack is not loaded)",
		want:     ">= min(pool size, admission limit) x 256, at most 262144",
		why:      "every masqueraded flow takes an entry and a full table drops new flows",
		evidence: "The kernel default scales with RAM: 8192 on a 960 MB exit, 65536 on 2 GB ones; no `table full` in their kernel logs (2026-10-24). 256 flows per client is an assumption, not a measurement",
		check:    minIntRule("net.netfilter.nf_conntrack_max", conntrackNeed),
	},
	{
		setting:  "net.core.somaxconn",
		when:     "always",
		want:     ">= min(admission limit, 4096)",
		why:      "Go uses it as the listen backlog; a reconnect storm overflows a short accept queue before admission control sees it",
		evidence: "4096 on every node we run (kernel >= 5.4 default; read 2026-10-24); older kernels default to 128. No overflow has been observed, the rule only catches an old kernel or a host tuned below the default",
		check:    minIntRule("net.core.somaxconn", somaxconnNeed),
	},
	{
		setting:  "RLIMIT_NOFILE",
		when:     "always",
		want:     ">= admission limit x 4 + 1024",
		why:      "each admitted connection holds a client socket and a target or upstream leg; below this accept fails with EMFILE",
		evidence: "Our nodes run 524287 (Go raises the soft limit to the hard one) or the 65536 the packaged unit sets (read 2026-10-24). Derived from admission control, not from an incident",
		check:    nofileRule,
	},
}

// adviseHostTuning runs every rule and returns the lines to log: one per
// setting that falls short, then a summary. skipped collects rules whose value
// could not be read, for a debug line.
func adviseHostTuning(in hostTuningInput, h hostReader) (lines []string, skipped []string) {
	checked, short := 0, 0
	for _, r := range hostTuningRules {
		adv, applies, err := r.check(in, h)
		if !applies {
			continue
		}
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", r.setting, err))
			continue
		}
		checked++
		if adv != nil {
			short++
			lines = append(lines, adv.line())
		}
	}
	summary := fmt.Sprintf("Host tuning: %d settings checked for this config, %d to adjust", checked, short)
	if short == 0 {
		summary = fmt.Sprintf("Host tuning: %d settings checked for this config, all fine", checked)
	}
	if len(skipped) > 0 {
		summary += fmt.Sprintf(", %d unreadable", len(skipped))
	}
	return append(lines, summary+"; the server changes none of them itself"), skipped
}

// logHostTuning is the startup entry point. Linux only: elsewhere the
// settings do not exist and the advisor stays silent.
func logHostTuning(cfg *Config, dualStack bool) {
	if runtime.GOOS != "linux" {
		log.Debug("Host tuning: skipped on %s", runtime.GOOS)
		return
	}
	lines, skipped := adviseHostTuning(hostTuningInputFor(cfg, dualStack), procHost{})
	for _, s := range skipped {
		log.Debug("Host tuning: cannot read %s", s)
	}
	for _, l := range lines {
		log.Info("%s", l)
	}
}

// hostTuningDocTable renders the rule table for docs/server.md.
func hostTuningDocTable() string {
	var b strings.Builder
	b.WriteString("| Setting | Checked when | Recommended | Why | Evidence |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, r := range hostTuningRules {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", r.setting, r.when, r.want, r.why, r.evidence)
	}
	return b.String()
}
