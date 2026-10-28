package server

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Host tuning advisor.
//
// At startup the server reads the kernel and process settings that decide how
// well it can run, compares each against what this server's own configuration
// asks of the host, and logs one line per setting that falls short, with the
// exact command to fix it. It never writes a setting itself: changing a host's
// kernel is the operator's call.
//
// Every rule is derived from the configuration rather than from a fixed list
// of "good values", and every rule says what it rests on: a measurement on our
// nodes, a hard requirement of the config, or an estimate. Measured and
// required shortfalls are logged at INFO; estimates only at DEBUG, marked
// "(unmeasured)", so they cannot drown out the measured ones. A buffer
// recommendation is only made while the host's TCP memory limit fits in half
// of the service's memory limit (see socketBufferBudget).
//
// The rule table below also generates the "Host tuning" section of
// docs/server.md (see TestHostTuningDocsInSync), so the two cannot drift.

const (
	// fdsPerConn is the estimated descriptor cost of one admitted connection:
	// the client socket, its target or upstream leg, and slack for a few mux
	// streams. An estimate, not a measurement.
	fdsPerConn = 4

	// fdHeadroom covers listeners, TUN, Redis, log files and the runtime.
	fdHeadroom = 1024

	// conntrackPerClient is the conntrack budget per TUN client behind this
	// host's MASQUERADE. An assumption: no per-client flow count has been
	// taken on our exits.
	conntrackPerClient = 256

	// conntrackCeiling caps the recommendation for very large pools.
	conntrackCeiling = 262144

	// conntrackEntryBytes is the slab size of one conntrack entry on our
	// kernels (256 on 6.8, 320 on 5.15; the larger is used).
	conntrackEntryBytes = 320

	// conntrackRAMShare is the fraction of host RAM (1/16) the conntrack
	// table may take at the recommended size.
	conntrackRAMShare = 16

	// hostTuningSysctlFile is the drop-in the persist hints point at.
	hostTuningSysctlFile = "/etc/sysctl.d/90-tiredvpn.conf"
)

// Basis of a rule: what the recommendation rests on. It decides the level.
const (
	basisMeasured = "measured" // measured on our nodes; INFO
	basisRequired = "required" // the config cannot work without it; INFO
	basisEstimate = "estimate" // reasoned, never measured; DEBUG
)

// hostTuningInput is what this server's configuration asks of the host.
type hostTuningInput struct {
	upstream    bool // -upstream: target and TUN traffic goes to the upstream exit
	upstreamBuf int  // socket buffer the upstream dialer requests
	// natV4 / natV6: a TUN pool whose traffic is forwarded and masqueraded out
	// of this host (an exit with -ip-pool, not a relay bridging to upstream).
	natV4, natV6   bool
	poolClients    int // usable addresses in the v4 pool
	admissionLimit int // TCP admission limit; QUIC and mux streams are not bounded by it
}

// hostTuningInputFor derives the input from the effective configuration.
// dualStack is the IP pool's own verdict (NAT66 is set up only then).
func hostTuningInputFor(cfg *Config, dualStack bool) hostTuningInput {
	in := hostTuningInput{
		upstream:       cfg.UpstreamAddr != "",
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

// poolDualStack is whether the server's IP pool came up dual-stack.
func poolDualStack(srvCtx *serverContext) bool {
	return srvCtx != nil && srvCtx.ipPool != nil && srvCtx.ipPool.DualStack()
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
// /proc, /sys/fs/cgroup and getrlimit; tests substitute a map.
type hostReader interface {
	// sysctl returns the value of a dotted sysctl name, e.g. net.core.rmem_max.
	sysctl(name string) (string, error)
	// nofileSoft returns the soft RLIMIT_NOFILE the process runs with.
	nofileSoft() (uint64, error)
	// memLimit returns the memory limit of this process's cgroup (the unit's
	// MemoryMax); limited is false when there is none.
	memLimit() (limit uint64, limited bool, err error)
	// memTotal returns the host RAM in bytes.
	memTotal() (uint64, error)
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

func (procHost) memLimit() (uint64, bool, error) {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, false, err
	}
	return cgroupMemLimit(string(self), os.ReadFile)
}

func (procHost) memTotal() (uint64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	return parseMemTotal(string(b))
}

// cgroupMemLimit returns the tightest memory limit on the path from this
// process's cgroup up to and including the root of its cgroup namespace (a
// container's own limit sits there). cgroup v2 (memory.max, "max" = none) and
// the v1 memory controller (memory.limit_in_bytes, a huge value = none) are
// understood. A level without the file is skipped (the global root has
// none); any other read error makes the limit unknown, never "none".
func cgroupMemLimit(selfCgroup string, readFile func(string) ([]byte, error)) (uint64, bool, error) {
	var root, dir, file string
	for line := range strings.SplitSeq(strings.TrimSpace(selfCgroup), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			if dir == "" {
				root, file = "/sys/fs/cgroup", "memory.max"
				dir = root + parts[2]
			}
		case strings.Contains(","+parts[1]+",", ",memory,"):
			root, file = "/sys/fs/cgroup/memory", "memory.limit_in_bytes"
			dir = root + parts[2]
		}
	}
	if dir == "" {
		return 0, false, errors.New("no memory cgroup in /proc/self/cgroup")
	}
	const v1Unlimited = 1 << 62
	var best uint64
	limited := false
	for p := strings.TrimSuffix(dir, "/"); ; {
		b, err := readFile(p + "/" + file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return 0, false, err
		default:
			v := strings.TrimSpace(string(b))
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				if n < v1Unlimited && (!limited || n < best) {
					best, limited = n, true
				}
			} else if v != "max" {
				return 0, false, fmt.Errorf("%s/%s: %q", p, file, v)
			}
		}
		if p == root || !strings.HasPrefix(p, root+"/") {
			break
		}
		p = p[:strings.LastIndexByte(p, '/')]
	}
	return best, limited, nil
}

func parseMemTotal(meminfo string) (uint64, error) {
	for line := range strings.SplitSeq(meminfo, "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 2 || f[1] != "kB" {
			return 0, fmt.Errorf("MemTotal: %q", line)
		}
		kb, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, errors.New("no MemTotal in /proc/meminfo")
}

// tuningAdvice is one setting that falls short of what the config needs.
type tuningAdvice struct {
	setting string
	current string
	want    string
	reason  string
	fix     string // what to do now
	persist string // how to keep it across reboots
}

func (a tuningAdvice) line(basis string) string {
	tag := ""
	if basis == basisEstimate {
		tag = " (unmeasured)"
	}
	s := fmt.Sprintf("Host tuning%s: %s is %s, recommended %s - %s. Fix: %s", tag, a.setting, a.current, a.want, a.reason, a.fix)
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
	basis    string // basisMeasured, basisRequired or basisEstimate
	why      string
	evidence string
	// check returns applies=false when the config does not need the setting,
	// a non-nil advice when the host falls short, and an error when a value
	// could not be read (the rule is then skipped, never guessed). current is
	// the value read, for the debug "ok" line.
	check func(in hostTuningInput, h hostReader) (adv *tuningAdvice, current string, applies bool, err error)
}

// netnsSysctls are kept per network namespace: a server in its own namespace
// (a container, a pod) reads and needs its namespace's value, and a sysctl -w
// on the host would not touch it. Every other sysctl the advisor reads is
// host-wide and can only be set on the host.
var netnsSysctls = map[string]bool{
	"net.core.somaxconn":              true,
	"net.ipv4.ip_forward":             true,
	"net.ipv6.conf.all.forwarding":    true,
	"net.ipv4.tcp_congestion_control": true,
}

// sysctlFix renders the runtime command and the sysctl.d line for one value,
// saying where it has to run.
func sysctlFix(name, value string) (fix, persist string) {
	cmd := fmt.Sprintf("sysctl -w %s=%s", name, value)
	persist = fmt.Sprintf("add '%s = %s' to %s", name, value, hostTuningSysctlFile)
	if netnsSysctls[name] {
		return fmt.Sprintf("%s in the server's network namespace (in a container: docker --sysctl %s=%s, or the pod's securityContext.sysctls)", cmd, name, value),
			persist + " (host namespace only)"
	}
	return "on the host, " + cmd, persist
}

func readInt(h hostReader, name string) (int64, error) {
	v, err := h.sysctl(name)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

const mib = 1 << 20

// socketBufferBudget decides whether raising a per-socket buffer ceiling is
// safe for this service.
//
// Nothing in the server bounds how many TCP sockets fill their buffers: one
// admitted connection can carry many mux streams, each with its own upstream
// socket, and QUIC opens sockets outside TCP admission. The only bound is the
// one the kernel enforces, the host-wide TCP memory limit (tcp_mem, third
// field), so that is the worst case. It must fit in half of the service's
// memory budget - its cgroup memory limit (MemoryMax), or host RAM without one
// - leaving the other half to the process.
//
// It returns ok, and otherwise the worst case and the budget for the line.
func socketBufferBudget(h hostReader) (ok bool, worst, budget uint64, budgetName string, err error) {
	total, err := h.memTotal()
	if err != nil {
		return false, 0, 0, "", err
	}
	limit, limited, err := h.memLimit()
	if err != nil {
		return false, 0, 0, "", err
	}
	budget, budgetName = total, "host RAM"
	if limited && limit < total {
		budget, budgetName = limit, "this unit's memory limit (MemoryMax)"
	}
	v, err := h.sysctl("net.ipv4.tcp_mem")
	if err != nil {
		return false, 0, 0, "", err
	}
	f := strings.Fields(v)
	if len(f) != 3 {
		return false, 0, 0, "", fmt.Errorf("net.ipv4.tcp_mem: want 3 fields, got %q", v)
	}
	pages, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil {
		return false, 0, 0, "", fmt.Errorf("net.ipv4.tcp_mem: %w", err)
	}
	worst = pages * uint64(os.Getpagesize())
	return worst <= budget/2, worst, budget, budgetName, nil
}

// relayBufRule checks rmem_max / wmem_max against the relay's upstream buffer.
// Exits are not checked: their target dials request 4 MiB, and lifting that
// clamp has a memory cost that has not been measured.
func relayBufRule(name string) func(hostTuningInput, hostReader) (*tuningAdvice, string, bool, error) {
	return func(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
		if !in.upstream {
			return nil, "", false, nil
		}
		cur, err := readInt(h, name)
		if err != nil {
			return nil, "", true, err
		}
		curS := strconv.FormatInt(cur, 10)
		want := int64(in.upstreamBuf)
		if cur >= want {
			return nil, curS, true, nil
		}
		w := strconv.FormatInt(want, 10)
		reason := fmt.Sprintf("the upstream dialer requests %d-byte socket buffers and the kernel silently clamps them to this ceiling", want)
		fix, persist := sysctlFix(name, w)
		fix += ", then restart the server (open sockets keep the clamped size)"
		ok, worst, budget, budgetName, err := socketBufferBudget(h)
		if err != nil {
			return nil, curS, true, err
		}
		if !ok {
			// Rounded so that applying either number clears the check.
			needMiB := (2*worst + mib - 1) / mib
			capPages := budget / 2 / uint64(os.Getpagesize())
			return &tuningAdvice{
				setting: name, current: curS, want: w + " only after the memory budget allows it",
				reason: reason + fmt.Sprintf(", but TCP socket memory may grow to %d MiB (net.ipv4.tcp_mem), more than half of %s (%d MiB)", (worst+mib-1)/mib, budgetName, budget/mib),
				fix:    fmt.Sprintf("raise the memory limit to at least %d MiB, or cap the third field of net.ipv4.tcp_mem at %d pages, first; until then leave %s as it is", needMiB, capPages, name),
			}, curS, true, nil
		}
		return &tuningAdvice{setting: name, current: curS, want: w, reason: reason, fix: fix, persist: persist}, curS, true, nil
	}
}

// equalsOneRule fires when a boolean sysctl is not 1 while the config needs it.
func equalsOneRule(name string, needed func(hostTuningInput) bool, reason string) func(hostTuningInput, hostReader) (*tuningAdvice, string, bool, error) {
	return func(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
		if !needed(in) {
			return nil, "", false, nil
		}
		v, err := h.sysctl(name)
		if err != nil {
			return nil, "", true, err
		}
		if v == "1" {
			return nil, v, true, nil
		}
		fix, persist := sysctlFix(name, "1")
		return &tuningAdvice{setting: name, current: v, want: "1", reason: reason, fix: fix, persist: persist}, v, true, nil
	}
}

func congestionRule(_ hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
	const name = "net.ipv4.tcp_congestion_control"
	cur, err := h.sysctl(name)
	if err != nil {
		return nil, "", true, err
	}
	// bbr, bbr2, bbr3: any BBR is what the rule asks for.
	if strings.HasPrefix(cur, "bbr") {
		return nil, cur, true, nil
	}
	fix, persist := sysctlFix(name, "bbr")
	if avail, err := h.sysctl("net.ipv4.tcp_available_congestion_control"); err != nil || !strings.Contains(" "+avail+" ", " bbr ") {
		fix = "on the host, modprobe tcp_bbr; then " + fix
		persist = "add 'tcp_bbr' to /etc/modules-load.d/tiredvpn.conf and '" + name + " = bbr' to " + hostTuningSysctlFile
	}
	fix += ", then restart the server (the listener keeps the algorithm it was created with)"
	return &tuningAdvice{
		setting: name, current: cur, want: "bbr",
		reason: "loss-based congestion control backs off on random loss over long-RTT paths; the setting is host-wide and changes every TCP flow on the host",
		fix:    fix, persist: persist,
	}, cur, true, nil
}

func conntrackNeed(in hostTuningInput, h hostReader) (int64, error) {
	total, err := h.memTotal()
	if err != nil {
		return 0, err
	}
	// QUIC serves TUN clients without TCP admission, so the whole pool counts.
	need := min(int64(in.poolClients)*conntrackPerClient, conntrackCeiling)
	return min(need, int64(total/conntrackRAMShare/conntrackEntryBytes)), nil
}

func conntrackRule(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
	const name = "net.netfilter.nf_conntrack_max"
	if !in.natV4 {
		return nil, "", false, nil
	}
	want, err := conntrackNeed(in, h)
	if err != nil {
		return nil, "", true, err
	}
	if want <= 0 {
		return nil, "", false, nil
	}
	cur, err := readInt(h, name)
	if err != nil {
		return nil, "", true, err
	}
	curS := strconv.FormatInt(cur, 10)
	w := strconv.FormatInt(want, 10)
	if cur >= want {
		// A big table on few buckets only lengthens the hash chains. Older
		// kernels default to 4 entries per bucket; fewer buckets than that is
		// advised. Unreadable buckets are not guessed at.
		const buckets = "net.netfilter.nf_conntrack_buckets"
		if b, err := readInt(h, buckets); err == nil && b < want/4 {
			bS := strconv.FormatInt(b, 10)
			return &tuningAdvice{
				setting: buckets, current: bS, want: w,
				reason:  fmt.Sprintf("the table holds %s entries on %s hash buckets, so lookups walk long chains", curS, bS),
				fix:     fmt.Sprintf("on the host, sysctl -w %s=%s", buckets, w),
				persist: fmt.Sprintf("add 'options nf_conntrack hashsize=%s' to /etc/modprobe.d/tiredvpn.conf", w),
			}, curS, true, nil
		}
		return nil, curS, true, nil
	}
	return &tuningAdvice{
		setting: name, current: curS, want: w,
		reason: fmt.Sprintf("every flow of up to %d TUN clients is masqueraded here at an assumed %d flows each, and a full table drops new flows", in.poolClients, conntrackPerClient),
		fix:    fmt.Sprintf("on the host, sysctl -w %s=%s net.netfilter.nf_conntrack_buckets=%s (buckets track the maximum, or hash chains grow)", name, w, w),
		persist: fmt.Sprintf("add 'nf_conntrack' to /etc/modules-load.d/tiredvpn.conf (sysctl.d runs before the module loads otherwise), 'options nf_conntrack hashsize=%s' to /etc/modprobe.d/tiredvpn.conf and '%s = %s' to %s",
			w, name, w, hostTuningSysctlFile),
	}, curS, true, nil
}

func somaxconnRule(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
	const name = "net.core.somaxconn"
	cur, err := readInt(h, name)
	if err != nil {
		return nil, "", true, err
	}
	curS := strconv.FormatInt(cur, 10)
	want := int64(min(in.admissionLimit, 4096))
	if cur >= want {
		return nil, curS, true, nil
	}
	w := strconv.FormatInt(want, 10)
	fix, persist := sysctlFix(name, w)
	return &tuningAdvice{
		setting: name, current: curS, want: w,
		reason: fmt.Sprintf("Go takes the listen backlog from it, and a reconnect storm can arrive faster than admission (%d) drains the queue", in.admissionLimit),
		fix:    fix + ", then restart the server (the backlog is fixed when the listener is created)", persist: persist,
	}, curS, true, nil
}

// nofileNeed saturates instead of overflowing on an absurd -max-conns.
func nofileNeed(in hostTuningInput) uint64 {
	return min(uint64(max(in.admissionLimit, 0)), 1<<40)*fdsPerConn + fdHeadroom
}

func nofileRule(in hostTuningInput, h hostReader) (*tuningAdvice, string, bool, error) {
	cur, err := h.nofileSoft()
	if err != nil {
		return nil, "", true, err
	}
	curS := strconv.FormatUint(cur, 10)
	want := nofileNeed(in)
	if cur >= want {
		return nil, curS, true, nil
	}
	w := strconv.FormatUint(want, 10)
	return &tuningAdvice{
		setting: "RLIMIT_NOFILE", current: curS, want: w,
		reason: fmt.Sprintf("at an estimated %d descriptors per connection, %d admitted connections need more, and mux streams and QUIC add descriptors admission does not bound", fdsPerConn, in.admissionLimit),
		fix:    fmt.Sprintf("set LimitNOFILE=%s in the [Service] section of the unit (docker: --ulimit nofile=%s:%s) and restart", w, w, w),
	}, curS, true, nil
}

var hostTuningRules = []hostTuningRule{
	{
		setting:  "net.core.rmem_max",
		when:     "`-upstream` (relay)",
		want:     ">= the relay's upstream buffer (`-relay-upstream-buf`, default 512 KiB), only while the host's TCP memory limit (`tcp_mem`) fits in half of the memory budget",
		basis:    basisMeasured,
		why:      "`SO_RCVBUF` above this is clamped without an error, so the receive window of the upstream leg is capped",
		evidence: "Relay on stock Ubuntu 24.04, 146 ms upstream leg (2026-10-24): 212992 held the leg at `rcv_ssthresh` 210439 and TUN downloads at 6.3-8.7 Mbit/s; 1 MiB gave 19.8-20.1 Mbit/s. Exits are not checked: their target dials request 4 MiB, and lifting that clamp can cost 8 MiB of kernel memory per slow download, which has not been measured",
		check:    relayBufRule("net.core.rmem_max"),
	},
	{
		setting:  "net.core.wmem_max",
		when:     "`-upstream` (relay)",
		want:     "same as `net.core.rmem_max`",
		basis:    basisMeasured,
		why:      "`SO_SNDBUF` is clamped the same way, capping how much the upstream leg keeps in flight",
		evidence: "Raised together with `rmem_max` in the relay measurement above, not measured on its own",
		check:    relayBufRule("net.core.wmem_max"),
	},
	{
		setting:  "net.ipv4.ip_forward",
		when:     "`-ip-pool` on an exit (no `-upstream`)",
		want:     "1",
		basis:    basisRequired,
		why:      "TUN clients' packets are forwarded out of this host; the server sets it at startup, so 0 here means its own attempt failed",
		evidence: "Set by the NAT bootstrap (internal/tun/nat_linux.go); the advisor runs after it and only reports",
		check: equalsOneRule("net.ipv4.ip_forward", func(in hostTuningInput) bool { return in.natV4 },
			"TUN clients' packets are forwarded out of this host and the server's own attempt to enable it failed"),
	},
	{
		setting:  "net.ipv6.conf.all.forwarding",
		when:     "`-ip-pool` with `-ip-pool-v6` on an exit",
		want:     "1",
		basis:    basisRequired,
		why:      "same as `ip_forward`, for the dual-stack pool",
		evidence: "Set by the NAT66 bootstrap; without it v6 inside the tunnel is blackholed",
		check: equalsOneRule("net.ipv6.conf.all.forwarding", func(in hostTuningInput) bool { return in.natV6 },
			"dual-stack TUN clients' IPv6 is forwarded out of this host and the server's own attempt to enable it failed"),
	},
	{
		setting:  "net.ipv4.tcp_congestion_control",
		when:     "always; the setting is host-wide and changes every TCP flow on the host",
		want:     "`bbr` (any version)",
		basis:    basisEstimate,
		why:      "loss-based cubic backs off on random loss over long-RTT paths",
		evidence: "One of the seven nodes read on 2026-10-24 runs bbr, six run cubic. No A/B throughput measurement has been made",
		check:    congestionRule,
	},
	{
		setting:  "net.netfilter.nf_conntrack_max",
		when:     "`-ip-pool` on an exit (skipped while nf_conntrack is not loaded)",
		want:     ">= pool size x 256, at most 262144 and at most 1/16 of host RAM at 320 bytes per entry; `nf_conntrack_buckets` at least a quarter of that (raised to match when advised)",
		basis:    basisEstimate,
		why:      "every masqueraded flow takes an entry and a full table drops new flows",
		evidence: "The kernel default scales with RAM and sets buckets equal to the maximum: 8192 on a 960 MB exit, 65536 on 2 GB ones; no `table full` in their kernel logs (2026-10-24). 256 flows per client is an assumption. The whole pool counts because QUIC serves TUN clients outside TCP admission",
		check:    conntrackRule,
	},
	{
		setting:  "net.core.somaxconn",
		when:     "always",
		want:     ">= min(admission limit, 4096)",
		basis:    basisEstimate,
		why:      "Go uses it as the listen backlog; a reconnect storm overflows a short accept queue before admission control sees it",
		evidence: "4096 on every node we run (kernel >= 5.4 default; read 2026-10-24); older kernels default to 128. No overflow has been observed, the rule only catches an old kernel or a host tuned below the default",
		check:    somaxconnRule,
	},
	{
		setting:  "RLIMIT_NOFILE",
		when:     "always",
		want:     ">= admission limit x 4 + 1024 (a floor: mux streams and QUIC are not bounded by admission)",
		basis:    basisEstimate,
		why:      "each admitted connection holds a client socket and a target or upstream leg, more with mux streams",
		evidence: "Our nodes run 524287 (Go raises the soft limit to the hard one) or the 65536 the packaged unit sets (read 2026-10-24). 4 descriptors per connection is an estimate, not a measurement",
		check:    nofileRule,
	},
}

// hostTuningReport is the advisor's verdict for one config on one host.
type hostTuningReport struct {
	info    []string // measured or required shortfalls, then the summary
	debug   []string // unmeasured shortfalls and settings that are fine
	skipped []string // settings that could not be read
}

// adviseHostTuning runs every rule. The summary is the last info line.
func adviseHostTuning(in hostTuningInput, h hostReader) hostTuningReport {
	var rep hostTuningReport
	checked, short, estimates := 0, 0, 0
	for _, r := range hostTuningRules {
		adv, cur, applies, err := r.check(in, h)
		if !applies {
			continue
		}
		if err != nil {
			rep.skipped = append(rep.skipped, fmt.Sprintf("%s: %v", r.setting, err))
			continue
		}
		checked++
		switch {
		case adv == nil:
			rep.debug = append(rep.debug, fmt.Sprintf("Host tuning: %s ok (%s)", r.setting, cur))
		case r.basis == basisEstimate:
			estimates++
			rep.debug = append(rep.debug, adv.line(r.basis))
		default:
			short++
			rep.info = append(rep.info, adv.line(r.basis))
		}
	}
	return rep.withSummary(in, checked, short, estimates)
}

func (rep hostTuningReport) withSummary(in hostTuningInput, checked, short, estimates int) hostTuningReport {
	unreadable := len(rep.skipped)
	changes := "the server changes none of them itself"
	if in.natV4 {
		changes = "the server changes none of them itself apart from enabling forwarding in the NAT bootstrap"
	}
	var s string
	switch {
	case unreadable > 0 && unreadable >= checked:
		s = fmt.Sprintf("Host tuning: inconclusive, %d of %d settings for this config could not be read (see -debug)", unreadable, checked+unreadable)
	case short == 0 && estimates == 0:
		s = fmt.Sprintf("Host tuning: %d settings checked for this config, all fine", checked)
	default:
		s = fmt.Sprintf("Host tuning: %d settings checked for this config, %d to adjust", checked, short)
		if estimates > 0 {
			s += fmt.Sprintf(", %d more unmeasured at debug level", estimates)
		}
	}
	if unreadable > 0 && unreadable < checked {
		s += fmt.Sprintf(", %d unreadable", unreadable)
	}
	rep.info = append(rep.info, s+"; "+changes)
	return rep
}

// logHostTuning is the startup entry point. Linux only: elsewhere the
// settings do not exist and the advisor stays silent. It must run after the
// IP pool and NAT bootstrap, so forwarding is read as the server leaves it.
func logHostTuning(cfg *Config, srvCtx *serverContext) {
	if runtime.GOOS != "linux" {
		log.Debug("Host tuning: skipped on %s", runtime.GOOS)
		return
	}
	rep := adviseHostTuning(hostTuningInputFor(cfg, poolDualStack(srvCtx)), procHost{})
	for _, s := range rep.skipped {
		log.Debug("Host tuning: cannot read %s", s)
	}
	for _, l := range rep.debug {
		log.Debug("%s", l)
	}
	for _, l := range rep.info {
		log.Info("%s", l)
	}
}

// hostTuningDocTable renders the rule table for docs/server.md.
func hostTuningDocTable() string {
	var b strings.Builder
	b.WriteString("| Setting | Checked when | Recommended | Basis | Why | Evidence |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range hostTuningRules {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", r.setting, r.when, r.want, r.basis, r.why, r.evidence)
	}
	return b.String()
}
