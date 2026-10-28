package server

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	hostTuningChildEnv = "TIREDVPN_TEST_HOST_TUNING_CHILD"
	// hostTuningSkipMarker is printed by a child that cannot set itself up,
	// so the parent can skip instead of failing.
	hostTuningSkipMarker = "HOST-TUNING-CHILD-SKIP: "
)

// hostTuningChildBuf is a -relay-upstream-buf no host's rmem_max reaches, so
// the relay rmem_max rule fires at INFO on every host (as advice or as a
// held-back line) and proves the config reached the advisor through Run.
const hostTuningChildBuf = 1 << 30

// runHostTuningChild starts Run in a child process (via wrap, e.g. unshare)
// and returns its log up to and including the host tuning summary.
func runHostTuningChild(t *testing.T, mode string, wrap ...string) []string {
	t.Helper()
	dir := t.TempDir()
	cert := selfSignedCertForTest(t)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePEM(t, certPath, "CERTIFICATE", cert.Certificate[0])
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey)))

	argv := append(wrap, os.Args[0], "-test.run=^TestHostTuningRunChild$")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), hostTuningChildEnv+"="+mode, "TIREDVPN_TEST_CERT="+certPath, "TIREDVPN_TEST_KEY="+keyPath)
	out, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = cmd.Stderr // a skip marker printed by the test framework lands here too
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start %v: %v", argv[0], err)
	}
	// Only the child started above is killed, never anything found by name.
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	type result struct {
		lines   []string
		summary bool
	}
	done := make(chan result, 1)
	go func() {
		var r result
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			l := sc.Text()
			r.lines = append(r.lines, l)
			if strings.Contains(l, hostTuningSkipMarker) {
				break
			}
			if strings.Contains(l, "Host tuning: ") && strings.Contains(l, "; the server changes none of them itself") {
				r.summary = true
				break
			}
		}
		done <- r
	}()
	select {
	case r := <-done:
		for _, l := range r.lines {
			if _, why, ok := strings.Cut(l, hostTuningSkipMarker); ok {
				t.Skip(why)
			}
		}
		if !r.summary {
			t.Fatalf("Run never logged the host tuning summary; output:\n%s", strings.Join(r.lines, "\n"))
		}
		return r.lines
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the host tuning summary")
	}
	return nil
}

func hasLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// TestHostTuningRunCallsAdvisor starts the real Run in a child process and
// waits for the advisor's INFO lines. Testing logHostTuning directly would
// pass with the call in Run deleted.
func TestHostTuningRunCallsAdvisor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the advisor only reads Linux settings")
	}
	lines := runHostTuningChild(t, "plain")
	want := "requests " + strconv.Itoa(hostTuningChildBuf) + "-byte socket buffers"
	if !hasLine(lines, "Host tuning: net.core.rmem_max is ") || !hasLine(lines, want) {
		t.Fatalf("no INFO rmem_max line for -relay-upstream-buf %d; output:\n%s", hostTuningChildBuf, strings.Join(lines, "\n"))
	}
}

// TestRootHostTuningReadsForwardingAfterNAT runs Run with a dual-stack pool in
// a network namespace of its own, where the child may create TUN and write
// forwarding. The child zeroes both forwarding switches first; the NAT
// bootstrap turns them on, so an advisor running after it reads 1 for both.
// Called before initIPPool, or without the dual-stack flag, it would not.
//
// CI runs it as root in the netns_tests job (TIREDVPN_NETNS_TESTS=1, already
// inside "sudo unshare -n"), where a skip fails the job. Elsewhere it uses an
// unprivileged user namespace when the host allows one.
func TestRootHostTuningReadsForwardingAfterNAT(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	var wrap []string
	if os.Getenv("TIREDVPN_NETNS_TESTS") == "1" {
		if os.Geteuid() != 0 {
			t.Skip("needs root: creates a TUN device and writes forwarding")
		}
	} else {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("unshare not installed")
		}
		if err := exec.Command(unshare, "-Urn", "true").Run(); err != nil {
			t.Skipf("unprivileged user namespaces unavailable: %v", err)
		}
		wrap = []string{unshare, "-Urn"}
	}
	lines := runHostTuningChild(t, "nat", wrap...)
	for _, want := range []string{"Host tuning: net.ipv4.ip_forward ok (1)", "Host tuning: net.ipv6.conf.all.forwarding ok (1)"} {
		if !hasLine(lines, want) {
			t.Errorf("no %q; output:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

// TestHostTuningRunChild is the child half of the two tests above. It blocks
// in Run's accept loop until the parent kills it.
func TestHostTuningRunChild(t *testing.T) {
	mode := os.Getenv(hostTuningChildEnv)
	if mode == "" {
		t.Skip("child process of the host tuning Run tests")
	}
	skip := func(why string) {
		os.Stderr.WriteString(hostTuningSkipMarker + why + "\n")
	}
	cfg := &Config{
		ListenAddr:           "127.0.0.1:0",
		Secret:               []byte("host-tuning-child"),
		CertFile:             os.Getenv("TIREDVPN_TEST_CERT"),
		KeyFile:              os.Getenv("TIREDVPN_TEST_KEY"),
		REALITYLegacyEnabled: true,
	}
	switch mode {
	case "plain":
		cfg.UpstreamAddr, cfg.UpstreamSecret = "exit.invalid:443", "host-tuning-child"
		cfg.RelayUpstreamBufBytes = hostTuningChildBuf
	case "nat":
		f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
		if err != nil {
			skip("no usable /dev/net/tun: " + err.Error())
			return
		}
		f.Close()
		for _, p := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
				skip("cannot write " + p + ": " + err.Error())
				return
			}
		}
		cfg.Debug = true // the "ok" lines are debug
		cfg.IPPoolNetwork, cfg.IPPoolV6 = "10.77.0.0/24", "fd00:77::/64"
		cfg.TunIP, cfg.TunName = net.IPv4(10, 77, 0, 1).To4(), "tvht0"
		// Loopback is down in a fresh network namespace; the wildcard binds
		// without it and is private to the namespace.
		cfg.ListenAddr = "0.0.0.0:0"
	}
	t.Fatal(Run(cfg))
}
func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestProcHostReadsTheRealHost runs the production reader against this host:
// the dotted names must reach the right files, values must come back trimmed,
// and the multi-field ones must split.
func TestProcHostReadsTheRealHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	h := procHost{}
	if _, err := readInt(h, "net.core.somaxconn"); err != nil {
		t.Errorf("net.core.somaxconn: %v", err)
	}
	if v, err := h.sysctl("net.ipv4.ip_forward"); err != nil || (v != "0" && v != "1") {
		t.Errorf("net.ipv4.ip_forward = %q, %v; want exactly 0 or 1", v, err)
	}
	if v, err := h.sysctl("net.ipv4.tcp_mem"); err != nil || len(strings.Fields(v)) != 3 {
		t.Errorf("net.ipv4.tcp_mem = %q, %v; want 3 fields", v, err)
	}
	if v, err := h.sysctl("net.ipv4.tcp_congestion_control"); err != nil || v == "" || strings.TrimSpace(v) != v {
		t.Errorf("net.ipv4.tcp_congestion_control = %q, %v", v, err)
	}
	total, err := h.memTotal()
	if err != nil || total < 64<<20 {
		t.Errorf("memTotal = %d, %v", total, err)
	}
	limit, limited, err := h.memLimit()
	if err != nil || (limited && limit == 0) {
		t.Errorf("memLimit = %d %v, %v", limit, limited, err)
	}
	if direct, dLimited, ok := ownCgroupV2MemLimit(t); ok && (direct != limit || dLimited != limited) {
		t.Errorf("memLimit = %d %v, direct read of memory.max along /proc/self/cgroup = %d %v", limit, limited, direct, dLimited)
	}
}

// TestProcHostNofileIsTheSoftLimit lowers the soft limit below the hard one
// (Go raises soft to hard at start, so they are usually equal) and checks
// the reader returns the soft value.
func TestProcHostNofileIsTheSoftLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	if orig.Max < 2048 {
		t.Skipf("hard limit %d too low to lower", orig.Max)
	}
	lowered := orig
	lowered.Cur = orig.Max - 1
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Skipf("cannot lower the soft limit: %v", err)
	}
	defer func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig) }()
	got, err := procHost{}.nofileSoft()
	if err != nil || got != uint64(lowered.Cur) {
		t.Fatalf("nofileSoft = %d, %v; want the soft limit %d (hard %d)", got, err, lowered.Cur, lowered.Max)
	}
}

// ownCgroupV2MemLimit reads memory.max at every level of this process's
// cgroup v2 path, namespace root included, independently of cgroupMemLimit.
// ok is false on a v1 or hybrid memory hierarchy.
func ownCgroupV2MemLimit(t *testing.T) (limit uint64, limited, ok bool) {
	t.Helper()
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, line := range strings.Split(strings.TrimSpace(string(self)), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) == 3 && strings.Contains(","+f[1]+",", ",memory,") {
			return 0, false, false
		}
		if len(f) == 3 && f[0] == "0" && f[1] == "" {
			path, ok = f[2], true
		}
	}
	if !ok {
		return 0, false, false
	}
	levels := []string{"/sys/fs/cgroup"}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part != "" {
			levels = append(levels, levels[len(levels)-1]+"/"+part)
		}
	}
	for _, dir := range levels {
		b, err := os.ReadFile(dir + "/memory.max")
		if err != nil {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil && (!limited || n < limit) {
			limit, limited = n, true
		}
	}
	return limit, limited, true
}

const memLimitChildEnv = "TIREDVPN_TEST_MEMLIMIT_CHILD"

// TestRootProcHostReadsMemoryMax runs the production reader in a child placed
// in a cgroup with a known memory.max: on an unlimited test host a reader that
// always says "no limit" would pass every other test. As root (the
// netns_tests job) the test makes the cgroup itself; otherwise it asks the
// user's systemd for a transient scope.
func TestRootProcHostReadsMemoryMax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	const limit = 314572800
	child := []string{os.Args[0], "-test.run=^TestProcHostMemLimitChild$", "-test.v"}
	var cmd *exec.Cmd
	var cgroupDir string
	if os.Geteuid() == 0 && os.Getenv("TIREDVPN_NETNS_TESTS") == "1" {
		cgroupDir = fmt.Sprintf("/sys/fs/cgroup/tiredvpn-test-%d", os.Getpid())
		if err := os.Mkdir(cgroupDir, 0o755); err != nil {
			t.Skipf("cannot create a cgroup: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroupDir) })
		if err := os.WriteFile(cgroupDir+"/memory.max", []byte(strconv.Itoa(limit)), 0o644); err != nil {
			t.Skipf("cannot set memory.max (memory controller not delegated?): %v", err)
		}
		cmd = exec.Command(child[0], child[1:]...)
	} else {
		run, err := exec.LookPath("systemd-run")
		if err != nil {
			t.Skip("not root and no systemd-run")
		}
		args := append([]string{"--user", "--scope", "-q", "-p", "MemoryMax=" + strconv.Itoa(limit)}, child...)
		cmd = exec.Command(run, args...)
	}
	cmd.Env = append(os.Environ(), memLimitChildEnv+"="+strconv.Itoa(limit))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start the child: %v", err)
	}
	if cgroupDir != "" {
		if err := os.WriteFile(cgroupDir+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("cannot move the child into %s: %v", cgroupDir, err)
		}
	}
	// The child reads its limit only after it has been placed.
	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	err = cmd.Wait()
	o := out.String()
	switch {
	case strings.Contains(o, "--- PASS: TestProcHostMemLimitChild"):
	case strings.Contains(o, hostTuningSkipMarker):
		t.Skipf("limit not applied to the child: %s", o)
	case cgroupDir == "" && !strings.Contains(o, "--- FAIL"):
		t.Skipf("no systemd user scope here: %v: %s", err, o)
	default:
		t.Fatalf("child: %v\n%s", err, o)
	}
}

func TestProcHostMemLimitChild(t *testing.T) {
	want := os.Getenv(memLimitChildEnv)
	if want == "" {
		t.Skip("child process of TestRootProcHostReadsMemoryMax")
	}
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	// A scope that was created but not limited is the host's doing, not the
	// reader's: report it as a skip.
	if direct, limited, ok := ownCgroupV2MemLimit(t); ok && (!limited || strconv.FormatUint(direct, 10) != want) {
		os.Stdout.WriteString(hostTuningSkipMarker + "cgroup memory.max is not " + want + "\n")
		return
	}
	limit, limited, err := procHost{}.memLimit()
	if err != nil || !limited || strconv.FormatUint(limit, 10) != want {
		t.Fatalf("memLimit = %d %v, %v; want %s", limit, limited, err, want)
	}
}
