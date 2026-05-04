//go:build integration_e2e

// tunnel_e2e_test wires a real client/server tunnel over a localhost TCP
// socket, with both endpoints configured from TOML files via
// tomlcfg.LoadClient / tomlcfg.LoadServer and shapers built through
// presets.FromConfig. It is the closest library-level approximation of the
// deployed data plane short of running the cmd/tiredvpn binary.
//
// Build tag (`integration_e2e`) keeps the suite opt-in:
//
//	go test -tags=integration_e2e -run TestTunnelE2E ./internal/integration/...
//
// The test deliberately skips the REALITY/TLS handshake — it focuses on the
// shaper + Morph framing path where the TOML wiring lives.

package integration_test

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	tomlcfg "github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// shaperFromTOML resolves the [shaper] section of a parsed TOML config into a
// concrete shaper.Shaper, using the same FromConfig entry point production
// code uses. The test fails fast if the section is missing.
func shaperFromTOML(t *testing.T, cfg *tomlcfg.ShaperConfig) shaper.Shaper {
	t.Helper()
	if cfg == nil {
		t.Fatal("[shaper] section missing in TOML")
	}
	sh, err := presets.FromConfig(*cfg)
	if err != nil {
		t.Fatalf("presets.FromConfig: %v", err)
	}
	return sh
}

// reflectListenAddr opens a fresh ephemeral 127.0.0.1 socket and rewrites the
// loaded server/client configs so they point at it. Validate() in the loader
// rejects port=0, so the TOML carries a placeholder port; the live port is
// patched in here. The listener is closed and a fresh listen is performed
// inside NewTestMorphedConnPairTCP, so this exists only to mirror the
// "deployment" code path where a port is chosen at startup and propagated
// into the rest of the runtime.
func reflectListenAddr(t *testing.T, srvCfg *tomlcfg.ServerConfig, cliCfg *tomlcfg.ClientConfig) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	srvCfg.Listen.Port = addr.Port
	cliCfg.Server.Address = addr.IP.String()
	cliCfg.Server.Port = addr.Port
}

// TestTunnelE2E_ChromePreset_RoundTrip drives 1 MiB of random data through a
// MorphedConn pair built end-to-end from TOML configs over a real loopback
// TCP socket. Asserts byte-perfect roundtrip within a fixed wall-clock budget.
func TestTunnelE2E_ChromePreset_RoundTrip(t *testing.T) {
	t.Parallel()

	cliCfg, err := tomlcfg.LoadClient(filepath.Join("testdata", "tunnel_e2e_client.toml"))
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	srvCfg, err := tomlcfg.LoadServer(filepath.Join("testdata", "tunnel_e2e_server.toml"))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}

	reflectListenAddr(t, srvCfg, cliCfg)

	clientShaper := shaperFromTOML(t, cliCfg.Shaper)
	serverShaper := shaperFromTOML(t, srvCfg.Shaper)

	profile := &strategy.TrafficProfile{
		Name:            "tunnel-e2e",
		PacketSizes:     []int{1200},
		PacketSizeProbs: []float64{1.0},
	}

	// NewTestMorphedConnPairTCP performs the listen/dial/accept on
	// 127.0.0.1:0 internally and wraps both ends with the supplied shapers.
	// We don't call NewMorphedConnWithShaper directly because the latter
	// performs a synchronous handshake Write that would interleave with the
	// echo loop and obscure shaper-level bytes; the Morph handshake is
	// covered by separate unit tests in internal/strategy.
	client, server, cleanup, err := strategy.NewTestMorphedConnPairTCP(profile, clientShaper, serverShaper)
	if err != nil {
		t.Fatalf("NewTestMorphedConnPairTCP: %v", err)
	}
	defer cleanup()

	const N = 1 << 20 // 1 MiB
	rng := rand.New(rand.NewPCG(0xDEADBEEF, 0xCAFEBABE))
	want := make([]byte, N)
	for i := range want {
		want[i] = byte(rng.UintN(256))
	}

	// Hard wall-clock deadline: shaper-driven flushes can take a few seconds
	// at 1 MiB on chrome_browsing, but minutes would indicate a deadlock.
	timer := time.AfterFunc(30*time.Second, func() {
		_ = client.Close()
		_ = server.Close()
	})
	defer timer.Stop()

	var (
		writeErr error
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, writeErr = client.Write(want)
		_ = client.Close()
	}()

	got, readErr := readAll(server, N, 30*time.Second)
	wg.Wait()

	if writeErr != nil {
		t.Fatalf("client write: %v", writeErr)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		t.Fatalf("server read: %v", readErr)
	}
	if !bytes.Equal(got[:N], want) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), N)
	}
}

// TestTunnelE2E_ConfigDrivenShaperGate verifies that the DataPlaneSafe gate
// is enforced when the shaper is materialised from a TOML config — a server
// operator who points [shaper].preset at a cover-traffic profile must get a
// hard error rather than a silently-broken tunnel.
func TestTunnelE2E_ConfigDrivenShaperGate(t *testing.T) {
	t.Parallel()

	srvCfg, err := tomlcfg.LoadServer(filepath.Join("testdata", "tunnel_e2e_server_unsafe_preset.toml"))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if srvCfg.Shaper == nil {
		t.Fatal("[shaper] section missing")
	}

	_, err = presets.FromConfig(*srvCfg.Shaper)
	if !errors.Is(err, presets.ErrPresetNotDataPlaneSafe) {
		t.Fatalf("FromConfig(bittorrent_idle): err=%v, want ErrPresetNotDataPlaneSafe", err)
	}
}
