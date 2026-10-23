package client

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// runCore runs one core in control-socket mode over pool until stop is
// called: a SIGINT on its signal channel, which is what the app's stopClient
// becomes (jni_context.go). before runs once the control socket listens.
func runCore(t *testing.T, mgr *strategy.Manager, pool []string, before func(sock string)) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	sig := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runControlSocketMode(&Config{ControlSocket: sock, ServerAddr: pool[0], TunMTU: 1280}, mgr, sig)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the control socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if before != nil {
		before(sock)
	}
	sig <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runControlSocketMode: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the core did not stop on SIGINT")
	}
}

// command sends one control command and waits for its answer.
func command(t *testing.T, sock, cmd string) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(cmd)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("%s: no answer: %v", cmd, err)
	}
}

// TestACoreShutdownKeepsTheCarryAUserStopDoesNot is P1-B of the round-6
// review, through the real shutdown: the app answers a dead connection by
// stopping the core (SIGINT) and starting a new one, and Close - which every
// shutdown runs - set the "user stopped" flag, so every carry was wiped. Only
// the host's "disconnect" command is the user's stop. P2-F: that stop also
// clears the endpoint parks of the selector the cores share.
func TestACoreShutdownKeepsTheCarryAUserStopDoesNot(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	parkFirst := func(m *strategy.Manager) {
		sess := &androidSession{mgr: m, linkUp: func() bool { return true }}
		ccfg := androidControlConfig(&Config{ServerAddr: pool[0], TunMTU: 1280}, m, false, sess)
		_, _, conn, err := ccfg.ConnectFn(t.Context())
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		conn.Close()
		ccfg.SessionEndedFn(tun.RelaySessionEnd{Lifetime: 2 * time.Minute, Degraded: true})
	}
	parked := func(m *strategy.Manager) bool {
		for _, st := range m.EndpointStates() {
			if st.Addr == pool[0] {
				return st.CooldownUntil.After(time.Now())
			}
		}
		t.Fatal("no state for the first server")
		return false
	}

	// A core shut down after a dead connection: the next one takes over.
	m := coreOn(t, pool, &dials, &mu)
	runCore(t, m, pool, func(string) { parkFirst(m) })
	androidCarry.mu.Lock()
	kept := !androidCarry.at.IsZero() && androidCarry.storm != nil
	androidCarry.mu.Unlock()
	if !kept {
		t.Fatal("a core shutdown wiped the carry")
	}
	next := coreOn(t, pool, &dials, &mu)
	carryInto(next)
	if !parked(next) {
		t.Fatal("the next core does not see the park")
	}

	// The user's stop: the "disconnect" command, then the shutdown.
	m = coreOn(t, pool, &dials, &mu)
	runCore(t, m, pool, func(sock string) {
		parkFirst(m)
		command(t, sock, `{"command":"disconnect"}`)
	})
	androidCarry.mu.Lock()
	cleared := androidCarry.at.IsZero()
	androidCarry.mu.Unlock()
	if !cleared {
		t.Fatal("the carry outlived the user's stop")
	}
	next = coreOn(t, pool, &dials, &mu)
	carryInto(next)
	if parked(next) {
		t.Fatal("the shared selector kept the park past the user's stop")
	}
}
