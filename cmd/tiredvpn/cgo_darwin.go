//go:build darwin && cgo
// +build darwin,cgo

package main

/*
#include <stdlib.h>
#include <stdint.h>

// Callback function pointer types.
// state_cb receives a state name ("connecting"/"connected"/"disconnected"/"error")
// and a JSON payload with details. log_cb receives a single log line (no trailing newline).
typedef void (*tv_state_cb)(const char* state, const char* json_data);
typedef void (*tv_log_cb)(const char* message);

// Proxies — cgo cannot call a raw C function pointer directly; we wrap the
// invocation in a static C function. The pointer is passed in as uintptr_t so
// it can be stored in a Go variable without violating cgo pointer rules.
static inline void tv_invoke_state(uintptr_t fn, const char* state, const char* json_data) {
    if (fn == 0) return;
    ((tv_state_cb)fn)(state, json_data);
}

static inline void tv_invoke_log(uintptr_t fn, const char* message) {
    if (fn == 0) return;
    ((tv_log_cb)fn)(message);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// All state guarded by a single mutex — Start/Stop are infrequent and ordered.
var (
	macMu     sync.Mutex
	macCancel context.CancelFunc
	macWg     sync.WaitGroup

	macTunFd int

	macStateCb uintptr // tv_state_cb pointer cast to uintptr_t
	macLogCb   uintptr // tv_log_cb pointer cast to uintptr_t
)

// macLogWriter forwards Go logs to the host process via log_cb.
type macLogWriter struct{}

func (macLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		macLog(msg)
	}
	return len(p), nil
}

// Register host-side callback function pointers. Pass 0 to unregister.
// The first call to this function also redirects the Go logger to log_cb.
//
//export TiredvpnSetCallbacks
func TiredvpnSetCallbacks(stateCb C.uintptr_t, logCb C.uintptr_t) {
	macMu.Lock()
	first := macLogCb == 0 && logCb != 0
	macStateCb = uintptr(stateCb)
	macLogCb = uintptr(logCb)
	macMu.Unlock()

	if first {
		log.SetOutput(macLogWriter{})
		log.SetColor(false)
		macLog("native: logging redirected to host")
	}
}

// Provide the utun file descriptor created by NEPacketTunnelProvider.
// Must be called before TiredvpnStart. Pass 0 to clear.
//
//export TiredvpnSetTunFd
func TiredvpnSetTunFd(fd C.int) {
	macMu.Lock()
	macTunFd = int(fd)
	macMu.Unlock()
	macLog(fmt.Sprintf("native: tun fd set to %d", int(fd)))
}

// Start the client with a JSON-encoded client.Config. Returns 0 on success,
// non-zero on argument error. The client runs in a background goroutine and
// reports its state via the registered state callback.
//
// If a client is already running it is stopped first.
//
//export TiredvpnStart
func TiredvpnStart(configJSON *C.char) C.int {
	if configJSON == nil {
		return 1
	}
	cfgStr := C.GoString(configJSON)

	macMu.Lock()
	// Stop any existing instance under the same lock to avoid races.
	if macCancel != nil {
		macLog("native: stopping existing client before restart")
		macCancel()
		macCancel = nil
	}
	tunFd := macTunFd
	macMu.Unlock()

	macWg.Wait() // ensure prior goroutine returned

	cfg := &client.Config{}
	if err := json.Unmarshal([]byte(cfgStr), cfg); err != nil {
		macLog(fmt.Sprintf("native: bad config JSON: %v", err))
		return 2
	}

	cfg.MacOSMode = true
	if tunFd > 0 {
		cfg.TunFd = tunFd
		cfg.TunMode = true
	}
	if cfg.ServerAddr == "" {
		macLog("native: missing server_addr in config")
		return 3
	}

	ctx, cancel := context.WithCancel(context.Background())

	macMu.Lock()
	macCancel = cancel
	macMu.Unlock()

	macWg.Add(1)
	go func() {
		defer macWg.Done()
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("native: panic: %v", r)
				macLog(msg)
				macState("error", fmt.Sprintf(`{"error":%q}`, msg))
			}
		}()

		macState("connecting", `{}`)
		if err := client.RunWithContext(ctx, cfg); err != nil {
			macLog(fmt.Sprintf("native: client exited with error: %v", err))
			macState("error", fmt.Sprintf(`{"error":%q}`, err.Error()))
			return
		}
		macState("disconnected", `{}`)
	}()

	return 0
}

// Stop the running client. Blocks until the background goroutine returns.
// Safe to call multiple times.
//
//export TiredvpnStop
func TiredvpnStop() {
	macMu.Lock()
	cancel := macCancel
	macCancel = nil
	macMu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	macWg.Wait()
	macState("disconnected", `{}`)
}

// Send a JSON command to the running client (port hop, status query, etc.).
// Returns a C string allocated by Go that the caller MUST free with
// TiredvpnFreeString. Returns nil if no client is running.
//
// Command shape is intentionally loose for now; the host and core agree on
// the schema separately. Currently this is a stub that echoes back.
//
//export TiredvpnSendCommand
func TiredvpnSendCommand(commandJSON *C.char) *C.char {
	if commandJSON == nil {
		return nil
	}
	cmd := C.GoString(commandJSON)
	resp := fmt.Sprintf(`{"status":"ok","echo":%q}`, cmd)
	return C.CString(resp)
}

// Free a C string returned by this library (e.g. from TiredvpnSendCommand).
//
//export TiredvpnFreeString
func TiredvpnFreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// Return the embedded version string. The returned pointer is static and
// must NOT be freed.
//
//export TiredvpnVersion
func TiredvpnVersion() *C.char {
	return C.CString(version)
}

// macState invokes the state callback if registered.
func macState(state, jsonData string) {
	macMu.Lock()
	fn := macStateCb
	macMu.Unlock()
	if fn == 0 {
		return
	}
	cState := C.CString(state)
	cJSON := C.CString(jsonData)
	defer C.free(unsafe.Pointer(cState))
	defer C.free(unsafe.Pointer(cJSON))
	C.tv_invoke_state(C.uintptr_t(fn), cState, cJSON)
}

// macLog invokes the log callback if registered.
func macLog(msg string) {
	macMu.Lock()
	fn := macLogCb
	macMu.Unlock()
	if fn == 0 {
		return
	}
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	C.tv_invoke_log(C.uintptr_t(fn), cMsg)
}
