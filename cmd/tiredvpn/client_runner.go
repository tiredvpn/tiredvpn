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
//
// Each client gets its own done channel. A single WaitGroup shared by every
// client cannot express this: when stop gives up after its deadline, the
// goroutine it left in Wait is still waiting when the next start calls Add,
// and Go panics with "WaitGroup is reused before previous Wait has returned".
// A channel per client has no such reuse, and a stop that gives up leaves
// nothing behind.
type clientRunner struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{} // closed when the current client returns
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
	done := make(chan struct{})
	r.cancel, r.done = cancel, done
	go func() {
		defer close(done)
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
	done := r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if announce != nil {
		announce()
	}

	select {
	case <-done:
		return true, true
	case <-time.After(timeout):
		return true, false
	}
}
