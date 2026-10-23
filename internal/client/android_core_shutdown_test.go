package client

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// runCore runs one core in control-socket mode over pool, as the app does:
// runControlSocketMode with its own control socket, stopped by stop on its
// signal channel (the app's stopClient becomes a SIGINT, jni_context.go).
// before runs once the socket listens, with the control configuration the
// core built, whose SessionEndedFn is where the relay reports a session end.
func runCore(t *testing.T, mgr *strategy.Manager, pool []string, stop os.Signal, before func(sock string, ctl *tun.ControlConfig)) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	var ctl *tun.ControlConfig
	built := make(chan struct{})
	onControlConfig = func(c *tun.ControlConfig) { ctl = c; close(built) }
	oldLink := localLinkUp
	localLinkUp = func() bool { return true }
	t.Cleanup(func() { onControlConfig, localLinkUp = nil, oldLink })
	sig := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runControlSocketMode(&Config{ControlSocket: sock, ServerAddr: pool[0], TunMTU: 1280}, mgr, sig)
	}()
	<-built
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
		before(sock, ctl)
	}
	sig <- stop
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runControlSocketMode: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the core did not stop on its signal")
	}
}

// command sends one control command and returns its answer.
func command(t *testing.T, sock, cmd string) string {
	t.Helper()
	// The socket file can be there a moment before the server accepts.
	c, err := net.Dial("unix", sock)
	for deadline := time.Now().Add(3 * time.Second); err != nil && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		c, err = net.Dial("unix", sock)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(cmd)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s: no answer: %v", cmd, err)
	}
	return string(buf[:n])
}

// connectThroughTheSocket asks the core to connect, as the app does, and
// returns where the dial went ("strategy@addr").
func connectThroughTheSocket(t *testing.T, sock string, dials *[]string, mu *sync.Mutex) string {
	t.Helper()
	if resp := command(t, sock, `{"command":"connect"}`); !strings.Contains(resp, "waiting_fd") {
		t.Fatalf("connect answered %s", resp)
	}
	mu.Lock()
	defer mu.Unlock()
	return (*dials)[len(*dials)-1]
}

// degraded is the relay's verdict on the session: a flow stalled and the
// keepalives went unanswered.
var degraded = tun.RelaySessionEnd{Lifetime: 2 * time.Minute, Degraded: true, Stall: 30 * time.Second}

// TestACoreShutdownKeepsTheCarryAUserStopDoesNot is P1-B of the round-6
// review, through the real shutdown: the app answers a dead connection by
// stopping the core and starting a new one, and Close - which every shutdown
// runs - set the "user stopped" flag, so every carry was wiped. Only the
// host's "disconnect" command is the user's stop. P2-F: that stop also
// forgets the endpoint parks of the selector the cores share, so the next
// core starts on the first server again.
func TestACoreShutdownKeepsTheCarryAUserStopDoesNot(t *testing.T) {
	for _, stop := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(stop.String(), func(t *testing.T) {
			pool := fourExitPool(t)
			t.Cleanup(clearCarry)
			var dials []string
			var mu sync.Mutex

			// A dead connection: the session on the first server ends
			// degraded, and the app stops the core.
			runCore(t, coreOn(t, pool, &dials, &mu), pool, stop, func(sock string, ctl *tun.ControlConfig) {
				if got := connectThroughTheSocket(t, sock, &dials, &mu); got != "reality@"+pool[0] {
					t.Fatalf("the first core dialled %s", got)
				}
				ctl.SessionEndedFn(degraded)
			})
			androidCarry.mu.Lock()
			kept := !androidCarry.at.IsZero() && androidCarry.storm != nil
			androidCarry.mu.Unlock()
			if !kept {
				t.Fatal("a core shutdown wiped the carry")
			}

			// The next core sees the park; this time the user stops it.
			runCore(t, coreOn(t, pool, &dials, &mu), pool, stop, func(sock string, ctl *tun.ControlConfig) {
				if got := connectThroughTheSocket(t, sock, &dials, &mu); strings.HasSuffix(got, "@"+pool[0]) {
					t.Fatalf("the core after a dead connection dialled %s, the server just parked", got)
				}
				command(t, sock, `{"command":"disconnect"}`)
			})
			androidCarry.mu.Lock()
			cleared := androidCarry.at.IsZero()
			androidCarry.mu.Unlock()
			if !cleared {
				t.Fatal("the carry outlived the user's stop")
			}

			// After the user's stop nothing is remembered: the first server
			// again, though its park has not run out.
			runCore(t, coreOn(t, pool, &dials, &mu), pool, stop, func(sock string, _ *tun.ControlConfig) {
				if got := connectThroughTheSocket(t, sock, &dials, &mu); got != "reality@"+pool[0] {
					t.Fatalf("the core after the user's stop dialled %s: the shared selector kept the park", got)
				}
			})
		})
	}
}

// send writes one control command and does not wait for its answer, as the
// app does with "disconnect" before it stops the core.
func send(t *testing.T, sock, cmd string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	for deadline := time.Now().Add(3 * time.Second); err != nil && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		c, err = net.Dial("unix", sock)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write([]byte(cmd)); err != nil {
		t.Fatal(err)
	}
	return c
}

// carryCleared reports whether the last core left no carry.
func carryCleared() bool {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	return androidCarry.at.IsZero()
}

// TestAUserStopTheAppDoesNotWaitForIsStillAStop is P3-2 of the round-7
// review. The app writes "disconnect" and stops the core at once, without
// reading the answer: the core often went before it had read the command,
// and the carry survived the user's stop in about one stop in five. A
// "disconnect" written while a "connect" was still running on the same
// connection was never read at all. And a "connect" after a "disconnect"
// in one core did not take the stop back.
func TestAUserStopTheAppDoesNotWaitForIsStillAStop(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	park := func(sock string, ctl *tun.ControlConfig) {
		connectThroughTheSocket(t, sock, &dials, &mu)
		ctl.SessionEndedFn(degraded)
	}

	t.Run("not waited for", func(t *testing.T) {
		for i := range 30 {
			runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
				// One connection for both, as the app's control channel.
				c := send(t, sock, `{"command":"connect"}`)
				if _, err := c.Read(make([]byte, 4096)); err != nil {
					t.Fatal(err)
				}
				ctl.SessionEndedFn(degraded)
				if _, err := c.Write([]byte(`{"command":"disconnect"}`)); err != nil {
					t.Fatal(err)
				}
			})
			if !carryCleared() {
				t.Fatalf("stop %d: the carry survived a disconnect the core was stopped right after", i+1)
			}
		}
	})

	t.Run("behind a running connect", func(t *testing.T) {
		runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, park)
		if carryCleared() {
			t.Fatal("no carry to clear - the test proves nothing")
		}
		hangingDial = true
		t.Cleanup(func() { hangingDial = false })
		runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
			c := send(t, sock, `{"command":"connect"}`)
			time.Sleep(100 * time.Millisecond) // the connect is dialling
			if _, err := c.Write([]byte(`{"command":"disconnect"}`)); err != nil {
				t.Fatal(err)
			}
		})
		hangingDial = false
		if !carryCleared() {
			t.Fatal("the carry survived a disconnect sent behind a running connect")
		}
	})

	t.Run("connect takes it back", func(t *testing.T) {
		runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
			command(t, sock, `{"command":"disconnect"}`)
			park(sock, ctl)
		})
		if carryCleared() {
			t.Fatal("a connect after a disconnect in the same core did not take the stop back")
		}
	})
}

// TestAHostThatHangsUpUnreadIsNoPanic is P3-9 of the round-7 review: a
// read that ends in an error after waiting - the host gone without reading
// the answer, the core's own stop cutting the read - returns n = -1, and
// buf[:n] panicked in the control server (recovered, and logged as an
// error). Here hosts hang up unread, and one stays connected and idle while
// the core stops.
func TestAHostThatHangsUpUnreadIsNoPanic(t *testing.T) {
	out := &lockedBuffer{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		for range 20 {
			// Gone for reading, still there for writing: the answer
			// fails, the core closes the connection under its blocked
			// reader.
			c := send(t, sock, `{"command":"status"}`)
			if err := c.(*net.UnixConn).CloseRead(); err != nil {
				t.Fatal(err)
			}
		}
		idle := send(t, sock, `{"command":"status"}`)
		if _, err := idle.Read(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	})
	if strings.Contains(out.String(), "panic") {
		t.Fatalf("the control server panicked:\n%s", out.String())
	}
}

// TestAStaleCarryIsNotTaken: P3-5 of the round-5 review and P3-3 of round 6.
// A carry is for the restart right after a dead connection; one older than
// androidCarryTTL is not taken. Its stamp is wall-clock time, so a phone
// asleep between the two cores sees the sleep.
func TestAStaleCarryIsNotTaken(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	park := func(sock string, ctl *tun.ControlConfig) {
		connectThroughTheSocket(t, sock, &dials, &mu)
		ctl.SessionEndedFn(degraded)
	}
	next := func() string {
		var got string
		runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
			got = connectThroughTheSocket(t, sock, &dials, &mu)
		})
		return got
	}

	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, park)
	androidCarry.mu.Lock()
	at := androidCarry.at
	androidCarry.mu.Unlock()
	if at.IsZero() || at != at.Round(0) {
		t.Fatalf("the carry is stamped %v: missing, or on a monotonic clock, which stops while the phone sleeps", at)
	}
	saved := snapshotCarry()
	if got := next(); got != "reality@"+pool[1] {
		t.Fatalf("a fresh carry was not taken: dialled %s - the test proves nothing", got)
	}

	// The same carry, androidCarryTTL older. The clock is not waited out:
	// the stamp is moved back.
	saved.at = saved.at.Add(-androidCarryTTL - time.Second)
	restoreCarry(saved)
	if got := next(); got != "reality@"+pool[0] {
		t.Fatalf("a stale carry was taken: dialled %s", got)
	}
}

// TestACarryFromAnotherPoolDoesNotKeepStaleParks is P2-3 of the round-7
// review: a degraded session parks the first server of pool X; the app then
// runs cores on pool Y, and comes back to X without a stop by the user. The
// carry from Y was fresh, so nothing reset X's selector, which the process
// had kept cached with the old park in it: the first dial on X skipped its
// first server. The carry names its pool; a core on another pool starts
// from nothing.
func TestACarryFromAnotherPoolDoesNotKeepStaleParks(t *testing.T) {
	x, y := fourExitPool(t), fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	runCore(t, coreOn(t, x, &dials, &mu), x, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
		if got := connectThroughTheSocket(t, sock, &dials, &mu); got != "reality@"+x[0] {
			t.Fatalf("the first core dialled %s", got)
		}
		ctl.SessionEndedFn(degraded)
	})
	runCore(t, coreOn(t, x, &dials, &mu), x, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		if got := connectThroughTheSocket(t, sock, &dials, &mu); got == "reality@"+x[0] {
			t.Fatal("the park on pool X did not hold for the next core - the test proves nothing")
		}
	})
	runCore(t, coreOn(t, y, &dials, &mu), y, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		connectThroughTheSocket(t, sock, &dials, &mu)
	})
	runCore(t, coreOn(t, x, &dials, &mu), x, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		if got := connectThroughTheSocket(t, sock, &dials, &mu); got != "reality@"+x[0] {
			t.Fatalf("back on pool X after a core on Y, the first dial went to %s: the cached park held", got)
		}
	})
}

// TestAndroidRouteVerdictCrossesCoresByAddress is P1-4 of the round-5 review
// and P3-2 of round 6, through the cores the app runs: every session ends
// degraded and the app restarts the core after each. REALITY dies on the
// first two servers, which is the route. The third core runs the same pool
// reordered, as an edited server list would: the set-aside follows the two
// servers it was decided on, so the new first server gets REALITY. Keyed by
// index it landed on the new first two, and that server got WebSocket.
func TestAndroidRouteVerdictCrossesCoresByAddress(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	var rode []string
	for range 2 {
		runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
			rode = append(rode, connectThroughTheSocket(t, sock, &dials, &mu))
			ctl.SessionEndedFn(degraded)
		})
	}
	if want := []string{"reality@" + pool[0], "reality@" + pool[1]}; fmt.Sprint(rode) != fmt.Sprint(want) {
		t.Fatalf("sessions rode %v, want %v", rode, want)
	}

	// Control, the same order: the third session leaves REALITY on b.
	reordered := []string{pool[2], pool[0], pool[1], pool[3]}
	same := func(order []string) string {
		var got string
		runCore(t, coreOn(t, order, &dials, &mu), order, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
			got = connectThroughTheSocket(t, sock, &dials, &mu)
		})
		return got
	}
	saved := snapshotCarry()
	if got := same(pool); got != "ws@"+pool[1] {
		t.Fatalf("the third core on the same pool dialled %s, want WebSocket on b - the test proves nothing", got)
	}
	restoreCarry(saved)
	if got := same(reordered); got != "reality@"+pool[2] {
		t.Fatalf("the third core on the reordered pool dialled %s, want REALITY on c", got)
	}
}

// carrySnapshot lets one carry feed two cores.
type carrySnapshot struct {
	health []endpoint.HealthRecord
	storm  *strategy.StormDetector
	route  strategy.RouteMemory
	pool   string
	at     time.Time
}

func snapshotCarry() carrySnapshot {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	return carrySnapshot{androidCarry.health, androidCarry.storm, androidCarry.route, androidCarry.pool, androidCarry.at}
}

func restoreCarry(c carrySnapshot) {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	androidCarry.health, androidCarry.storm, androidCarry.route = c.health, c.storm, c.route
	androidCarry.pool, androidCarry.at = c.pool, c.at
}
