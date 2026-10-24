package server

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

// hostTuningChildMaxConns is far above any RLIMIT_NOFILE a kernel allows
// (fs.nr_open tops out just under 2^30), so the RLIMIT_NOFILE rule fires on
// every host and its line proves the config reached the advisor through Run.
const hostTuningChildMaxConns = 1 << 28

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
// waits for the advisor's lines. Testing logHostTuning directly would pass
// with the call in Run deleted.
func TestHostTuningRunCallsAdvisor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the advisor only reads Linux settings")
	}
	lines := runHostTuningChild(t, "plain")
	want := strconv.Itoa(hostTuningChildMaxConns*fdsPerConn + fdHeadroom)
	if !hasLine(lines, "Host tuning (unmeasured): RLIMIT_NOFILE is ") || !hasLine(lines, "recommended "+want+" - ") {
		t.Fatalf("no RLIMIT_NOFILE line for -max-conns %d; output:\n%s", hostTuningChildMaxConns, strings.Join(lines, "\n"))
	}
}

// TestHostTuningRunReadsForwardingAfterNAT runs Run with a dual-stack pool in
// a private user and network namespace, where the child may create TUN and
// write forwarding. The child zeroes both forwarding switches first; the NAT
// bootstrap turns them on, so an advisor running after it reads 1 for both.
// Called before initIPPool it would read 0 and miss the dual-stack pool.
func TestHostTuningRunReadsForwardingAfterNAT(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not installed")
	}
	if err := exec.Command(unshare, "-Urn", "true").Run(); err != nil {
		t.Skipf("unprivileged user namespaces unavailable: %v", err)
	}
	lines := runHostTuningChild(t, "nat", unshare, "-Urn")
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
		t.Skip("child process of TestHostTuningRun*")
	}
	cfg := &Config{
		ListenAddr:           "127.0.0.1:0",
		Secret:               []byte("host-tuning-child"),
		CertFile:             os.Getenv("TIREDVPN_TEST_CERT"),
		KeyFile:              os.Getenv("TIREDVPN_TEST_KEY"),
		REALITYLegacyEnabled: true,
		MaxConcurrentConns:   hostTuningChildMaxConns,
		Debug:                true,
	}
	if mode == "nat" {
		for _, p := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
				os.Stderr.WriteString(hostTuningSkipMarker + "cannot write " + p + ": " + err.Error() + "\n")
				return
			}
		}
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
	if limit, limited, err := h.memLimit(); err != nil || (limited && limit == 0) {
		t.Errorf("memLimit = %d %v, %v", limit, limited, err)
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

const memLimitChildEnv = "TIREDVPN_TEST_MEMLIMIT_CHILD"

// TestProcHostReadsTheUnitMemoryLimit runs the production reader inside a
// transient systemd scope with a known MemoryMax: an unlimited test host
// could not tell a working reader from one that always says "no limit".
func TestProcHostReadsTheUnitMemoryLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("systemd-run not installed")
	}
	const limit = 314572800
	cmd := exec.Command(run, "--user", "--scope", "-q", "-p", "MemoryMax="+strconv.Itoa(limit),
		os.Args[0], "-test.run=^TestProcHostMemLimitChild$", "-test.v")
	cmd.Env = append(os.Environ(), memLimitChildEnv+"="+strconv.Itoa(limit))
	out, err := cmd.CombinedOutput()
	switch {
	case strings.Contains(string(out), "--- PASS: TestProcHostMemLimitChild"):
	case err != nil && !strings.Contains(string(out), "--- FAIL"):
		t.Skipf("no systemd user scope here: %v: %s", err, out)
	default:
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func TestProcHostMemLimitChild(t *testing.T) {
	want := os.Getenv(memLimitChildEnv)
	if want == "" {
		t.Skip("child process of TestProcHostReadsTheUnitMemoryLimit")
	}
	limit, limited, err := procHost{}.memLimit()
	if err != nil || !limited || strconv.FormatUint(limit, 10) != want {
		t.Fatalf("memLimit = %d %v, %v; want %s", limit, limited, err, want)
	}
}
