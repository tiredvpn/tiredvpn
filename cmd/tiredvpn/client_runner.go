package main

import (
	"context"
	"sync"
	"time"
)

// This file has no build tag on purpose: the start/stop bookkeeping behind
// the JNI startClient/stopClient exports lives here so the Linux CI can run
// it. jni_android.go only adds the JNI plumbing around it.

// clientRunner runs at most one client at a time. Starting cancels the client
// already running (without waiting for it); stopping cancels it and waits a
// bounded time for it to return.
type clientRunner struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// cancelCurrent cancels the running client, if any, and reports whether
// there was one. It does not wait.
func (r *clientRunner) cancelCurrent() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil {
		return false
	}
	r.cancel()
	r.cancel = nil
	return true
}

// start cancels any running client and runs run in a new goroutine with a
// fresh context.
func (r *clientRunner) start(run func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		run(ctx)
	}()
}

// stop cancels the running client and waits up to timeout for it to return.
// announce, if set, runs after the cancel and before the wait. wasRunning is
// false when there was nothing to stop; stopped is false when the client was
// still running at the deadline.
func (r *clientRunner) stop(timeout time.Duration, announce func()) (wasRunning, stopped bool) {
	r.mu.Lock()
	if r.cancel == nil {
		r.mu.Unlock()
		return false, false
	}
	r.cancel()
	r.cancel = nil
	r.mu.Unlock()
	if announce != nil {
		announce()
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true, true
	case <-time.After(timeout):
		return true, false
	}
}
