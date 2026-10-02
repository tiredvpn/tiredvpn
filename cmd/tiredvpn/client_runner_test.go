package main

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestClientRunnerFastRestart is the host's stop -> start cycle at speed,
// with some clients slower to shut down than stop is willing to wait - on a
// device that is a client still finishing a TUN handshake when the host gives
// up on it after 5s. Restarting must never trip over the previous client's
// bookkeeping: the device died here with "sync: WaitGroup is reused before
// previous Wait has returned".
func TestClientRunnerFastRestart(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		runtime.GOMAXPROCS(4)
		t.Cleanup(func() { runtime.GOMAXPROCS(1) })
	}
	const (
		cycles      = 400
		stopTimeout = 2 * time.Millisecond
	)
	var r clientRunner
	var running atomic.Int32
	var timedOut, fastStopped int
	for i := range cycles {
		slow := i%3 == 0 // every third client outlives the stop deadline
		r.start(func(ctx context.Context) {
			running.Add(1)
			defer running.Add(-1)
			<-ctx.Done()
			if slow {
				time.Sleep(3 * stopTimeout)
			}
		})
		if wasRunning, stopped := r.stop(stopTimeout, nil); !wasRunning {
			t.Fatalf("cycle %d: stop found nothing running", i)
		} else if !stopped {
			timedOut++
		} else if !slow {
			fastStopped++
		}
	}
	if timedOut == 0 {
		t.Fatal("positive control: no stop ever hit its deadline, the slow path was not exercised")
	}
	if fastStopped == 0 {
		t.Fatal("no stop ever saw its client return: stop is not waiting on the client it cancelled")
	}
	// Every client returns in the end; nothing is left running.
	deadline := time.Now().Add(2 * time.Second)
	for running.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := running.Load(); n != 0 {
		t.Errorf("%d clients still running after all stops", n)
	}
}

// TestClientRunnerStopIsBounded: a client that ignores cancellation must not
// hang stop.
func TestClientRunnerStopIsBounded(t *testing.T) {
	var r clientRunner
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r.start(func(context.Context) { <-release })
	begin := time.Now()
	wasRunning, stopped := r.stop(50*time.Millisecond, nil)
	if !wasRunning || stopped {
		t.Fatalf("stop on a stuck client: wasRunning=%v stopped=%v", wasRunning, stopped)
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("stop took %v with a 50ms deadline", d)
	}
	if wasRunning, _ := r.stop(50*time.Millisecond, nil); wasRunning {
		t.Error("second stop found a client running")
	}
}

// TestClientRunnerStartReplaces: startClient on top of a running client (the
// host restarting without a stop in between) cancels the old one, so two
// cores never run side by side on the same control socket.
func TestClientRunnerStartReplaces(t *testing.T) {
	var r clientRunner
	firstDone := make(chan struct{})
	r.start(func(ctx context.Context) {
		<-ctx.Done()
		close(firstDone)
	})
	r.start(func(ctx context.Context) { <-ctx.Done() })
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("starting a new client left the previous one running")
	}
	if wasRunning, stopped := r.stop(time.Second, nil); !wasRunning || !stopped {
		t.Errorf("stop after replace: wasRunning=%v stopped=%v", wasRunning, stopped)
	}
}
