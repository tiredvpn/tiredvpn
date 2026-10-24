package server

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const hostTuningChildEnv = "TIREDVPN_TEST_HOST_TUNING_CHILD"

// hostTuningChildMaxConns is far above any RLIMIT_NOFILE a kernel allows
// (fs.nr_open tops out just under 2^30), so the RLIMIT_NOFILE rule fires on
// every host and its line proves the config reached the advisor through Run.
const hostTuningChildMaxConns = 1 << 28

// TestHostTuningRunCallsAdvisor starts the real Run in a child process and
// waits for the advisor's lines. Testing logHostTuning directly would pass
// with the call in Run deleted.
func TestHostTuningRunCallsAdvisor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the advisor only reads Linux settings")
	}
	dir := t.TempDir()
	cert := selfSignedCertForTest(t)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePEM(t, certPath, "CERTIFICATE", cert.Certificate[0])
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey)))

	cmd := exec.Command(os.Args[0], "-test.run=^TestHostTuningRunChild$")
	cmd.Env = append(os.Environ(), hostTuningChildEnv+"=1", "TIREDVPN_TEST_CERT="+certPath, "TIREDVPN_TEST_KEY="+keyPath)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Only the child started above is killed, never anything found by name.
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	want := strconv.Itoa(hostTuningChildMaxConns*fdsPerConn + fdHeadroom)
	found := make(chan [2]bool, 1)
	var seen []string
	go func() {
		var nofile, summary bool
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			l := sc.Text()
			seen = append(seen, l)
			if strings.Contains(l, "Host tuning: RLIMIT_NOFILE is ") && strings.Contains(l, "recommended "+want+" - ") {
				nofile = true
			}
			if strings.Contains(l, "Host tuning: ") && strings.Contains(l, " settings checked for this config") {
				summary = true
				break
			}
		}
		found <- [2]bool{nofile, summary}
	}()
	select {
	case got := <-found:
		if !got[1] {
			t.Fatalf("Run never logged the host tuning summary; output:\n%s", strings.Join(seen, "\n"))
		}
		if !got[0] {
			t.Fatalf("summary logged without the RLIMIT_NOFILE line for -max-conns %d; output:\n%s", hostTuningChildMaxConns, strings.Join(seen, "\n"))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the host tuning lines") // seen is still being written, not printed
	}
}

// TestHostTuningRunChild is the child half of TestHostTuningRunCallsAdvisor.
// It blocks in Run's accept loop until the parent kills it.
func TestHostTuningRunChild(t *testing.T) {
	if os.Getenv(hostTuningChildEnv) != "1" {
		t.Skip("child process of TestHostTuningRunCallsAdvisor")
	}
	cfg := &Config{
		ListenAddr:           "127.0.0.1:0",
		Secret:               []byte("host-tuning-child"),
		CertFile:             os.Getenv("TIREDVPN_TEST_CERT"),
		KeyFile:              os.Getenv("TIREDVPN_TEST_KEY"),
		REALITYLegacyEnabled: true,
		MaxConcurrentConns:   hostTuningChildMaxConns,
	}
	t.Fatal(Run(cfg))
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
