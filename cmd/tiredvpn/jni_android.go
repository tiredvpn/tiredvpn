//go:build android
// +build android

package main

/*
#cgo LDFLAGS: -landroid -llog

#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TiredVPN-JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Global JNI environment and class reference for callbacks
static JavaVM* g_vm = NULL;
static jobject g_callback_obj = NULL;
static jmethodID g_state_callback_mid = NULL;
static jmethodID g_log_callback_mid = NULL;

// Helper functions for JNI string conversion
static inline const char* jni_get_string_chars(JNIEnv* env, jstring str) {
    return (*env)->GetStringUTFChars(env, str, NULL);
}

static inline void jni_release_string_chars(JNIEnv* env, jstring str, const char* chars) {
    (*env)->ReleaseStringUTFChars(env, str, chars);
}

static inline jstring jni_new_string(JNIEnv* env, const char* str) {
    return (*env)->NewStringUTF(env, str);
}

// Helpers for decoding a Java String[] (jobjectArray) argv element-by-element.
// argv is passed as a real string array so values containing spaces (e.g.
// "morph_Yandex Video") survive intact instead of being split on whitespace.
static inline jsize jni_array_length(JNIEnv* env, jobjectArray arr) {
    if (arr == NULL) return 0;
    return (*env)->GetArrayLength(env, arr);
}

// Returns a freshly UTF-8 chars pointer for element i; caller must release with
// jni_array_release_element. Returns NULL for a null element.
static inline const char* jni_array_get_element(JNIEnv* env, jobjectArray arr, jsize i) {
    jstring s = (jstring)(*env)->GetObjectArrayElement(env, arr, i);
    if (s == NULL) return NULL;
    return (*env)->GetStringUTFChars(env, s, NULL);
}

static inline void jni_array_release_element(JNIEnv* env, jobjectArray arr, jsize i, const char* chars) {
    if (chars == NULL) return;
    jstring s = (jstring)(*env)->GetObjectArrayElement(env, arr, i);
    if (s != NULL) {
        (*env)->ReleaseStringUTFChars(env, s, chars);
        (*env)->DeleteLocalRef(env, s);
    }
}

// Initialize JNI global state
static inline void jni_init(JNIEnv* env, jobject callback_obj) {
    if (g_vm == NULL) {
        (*env)->GetJavaVM(env, &g_vm);
    }

    // Check if old global ref is still valid before deleting
    if (g_callback_obj != NULL) {
        // IsSameObject returns JNI_TRUE if ref is valid, JNI_FALSE if deleted/invalid
        if ((*env)->IsSameObject(env, g_callback_obj, NULL) == JNI_FALSE) {
            // Reference is still valid, safe to delete
            (*env)->DeleteGlobalRef(env, g_callback_obj);
        } else {
            // Reference is invalid (already deleted), just clear it
            LOGD("Clearing invalid global ref");
        }
    }
    g_callback_obj = (*env)->NewGlobalRef(env, callback_obj);

    // Get callback method IDs
    jclass cls = (*env)->GetObjectClass(env, callback_obj);
    g_state_callback_mid = (*env)->GetMethodID(env, cls, "onStateChange", "(Ljava/lang/String;Ljava/lang/String;)V");
    g_log_callback_mid = (*env)->GetMethodID(env, cls, "onLogMessage", "(Ljava/lang/String;)V");

    LOGD("JNI initialized successfully");
}

// Cleanup JNI global state
static inline void jni_cleanup(JNIEnv* env) {
    if (g_callback_obj != NULL) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
    }
    g_state_callback_mid = NULL;
    g_log_callback_mid = NULL;
    LOGD("JNI cleaned up");
}

// Call back to Java for state changes
static inline void jni_state_callback(const char* state, const char* json_data) {
    if (g_vm == NULL || g_callback_obj == NULL || g_state_callback_mid == NULL) {
        LOGE("State callback not initialized");
        return;
    }

    JNIEnv* env = NULL;
    int attach_status = (*g_vm)->AttachCurrentThread(g_vm, &env, NULL);
    if (attach_status != JNI_OK || env == NULL) {
        LOGE("Failed to attach thread for callback");
        return;
    }

    jstring j_state = (*env)->NewStringUTF(env, state);
    jstring j_json = (*env)->NewStringUTF(env, json_data);

    (*env)->CallVoidMethod(env, g_callback_obj, g_state_callback_mid, j_state, j_json);

    // Check for JNI exceptions
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, j_state);
    (*env)->DeleteLocalRef(env, j_json);

    // Don't detach - Go runtime manages thread lifecycle for CGO calls
    // Detaching would break subsequent callbacks from the same Go thread
}

// Call back to Java for log messages
static inline void jni_log_callback(const char* message) {
    if (g_vm == NULL || g_callback_obj == NULL || g_log_callback_mid == NULL) {
        return; // Silently ignore if not initialized
    }

    JNIEnv* env = NULL;
    int attach_status = (*g_vm)->AttachCurrentThread(g_vm, &env, NULL);
    if (attach_status != JNI_OK || env == NULL) {
        return;
    }

    jstring j_message = (*env)->NewStringUTF(env, message);
    (*env)->CallVoidMethod(env, g_callback_obj, g_log_callback_mid, j_message);

    // Check for JNI exceptions
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, j_message);

    // Don't detach - Go runtime manages thread lifecycle for CGO calls
    // Detaching would break subsequent callbacks from the same Go thread
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

var (
	// Global client context and cancel function
	clientCtx    context.Context
	clientCancel context.CancelFunc
	clientMutex  sync.Mutex
	clientWg     sync.WaitGroup

	// TUN file descriptor passed from Android
	tunFd     int
	tunFdLock sync.Mutex
)

// androidLogWriter implements io.Writer to forward Go logs to Android logcat via JNI
type androidLogWriter struct{}

func (w *androidLogWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Remove trailing newline if present
	msg := string(p)
	msg = strings.TrimSuffix(msg, "\n")
	if msg != "" {
		logMessage(msg)
	}
	return len(p), nil
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_initNative
func Java_com_tiredvpn_android_native_TiredVpnNative_initNative(
	env *C.JNIEnv,
	class C.jclass,
	callback C.jobject,
) {
	C.jni_init(env, callback)

	// Redirect all Go logs to Android logcat via JNI
	log.SetOutput(&androidLogWriter{})
	log.SetColor(false) // Disable color codes for Android logs

	logMessage("Native library initialized - logging redirected to logcat")
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_cleanupNative
func Java_com_tiredvpn_android_native_TiredVpnNative_cleanupNative(
	env *C.JNIEnv,
	class C.jclass,
) {
	C.jni_cleanup(env)
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_startClient
func Java_com_tiredvpn_android_native_TiredVpnNative_startClient(
	env *C.JNIEnv,
	class C.jclass,
	argv C.jobjectArray,
) C.jint {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	// Stop any existing client
	if clientCancel != nil {
		logMessage("Stopping existing client before starting new one")
		clientCancel()
		clientCtx = nil
		clientCancel = nil
	}

	// Decode the Java String[] element-by-element. Each element is one argv
	// token already, so no space splitting happens here: values containing
	// spaces (e.g. a "morph_Yandex Video" strategy ID) survive intact.
	n := int(C.jni_array_length(env, argv))
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		cStr := C.jni_array_get_element(env, argv, C.jsize(i))
		if cStr == nil {
			continue // skip null elements defensively
		}
		args = append(args, C.GoString(cStr))
		C.jni_array_release_element(env, argv, C.jsize(i), cStr)
	}

	logMessage(fmt.Sprintf("Starting client with %d args: %s", len(args), strings.Join(args, " ")))

	if len(args) == 0 {
		logMessage("ERROR: No arguments provided")
		return 1
	}

	// Set up os.Args for flag parsing
	os.Args = append([]string{"tiredvpn", "client"}, args...)

	// Create cancelable context
	clientCtx, clientCancel = context.WithCancel(context.Background())

	// Run client in goroutine
	clientWg.Add(1)
	go func() {
		defer clientWg.Done()
		defer func() {
			if r := recover(); r != nil {
				errMsg := fmt.Sprintf("Client panicked: %v", r)
				logMessage(errMsg)
				sendStateChange("error", fmt.Sprintf(`{"error":"%s"}`, errMsg))
			}
		}()

		// Notify started state
		sendStateChange("connecting", `{}`)

		// Run the client (this will block until disconnect)
		if err := runClientWithContext(clientCtx, args); err != nil {
			errMsg := fmt.Sprintf("Client error: %v", err)
			logMessage(errMsg)
			sendStateChange("error", fmt.Sprintf(`{"error":"%s"}`, errMsg))
		} else {
			sendStateChange("disconnected", `{}`)
		}
	}()

	return 0
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_stopClient
func Java_com_tiredvpn_android_native_TiredVpnNative_stopClient(
	env *C.JNIEnv,
	class C.jclass,
) {
	clientMutex.Lock()

	if clientCancel != nil {
		logMessage("Stopping client")
		clientCancel()
		clientCtx = nil
		clientCancel = nil

		clientMutex.Unlock()

		// Wait for client goroutine to finish (with timeout)
		done := make(chan struct{})
		go func() {
			clientWg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logMessage("Client stopped successfully")
		case <-time.After(5 * time.Second):
			logMessage("WARNING: Client did not stop within 5 seconds")
		}

		sendStateChange("disconnected", `{}`)
	} else {
		clientMutex.Unlock()
	}
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_setTunFd
func Java_com_tiredvpn_android_native_TiredVpnNative_setTunFd(
	env *C.JNIEnv,
	class C.jclass,
	fd C.jint,
) {
	tunFdLock.Lock()
	defer tunFdLock.Unlock()

	tunFd = int(fd)
	logMessage(fmt.Sprintf("TUN fd set to: %d", tunFd))
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_getTunFd
func Java_com_tiredvpn_android_native_TiredVpnNative_getTunFd(
	env *C.JNIEnv,
	class C.jclass,
) C.jint {
	tunFdLock.Lock()
	defer tunFdLock.Unlock()

	return C.jint(tunFd)
}

//export Java_com_tiredvpn_android_native_TiredVpnNative_sendCommand
func Java_com_tiredvpn_android_native_TiredVpnNative_sendCommand(
	env *C.JNIEnv,
	class C.jclass,
	cmdStr C.jstring,
) C.jstring {
	// Convert Java string to Go
	cStr := C.jni_get_string_chars(env, cmdStr)
	goCmdStr := C.GoString(cStr)
	C.jni_release_string_chars(env, cmdStr, cStr)

	logMessage(fmt.Sprintf("Command received: %s", goCmdStr))

	// TODO: Implement command handling (for port hopping, etc.)
	response := fmt.Sprintf(`{"status":"ok","command":"%s"}`, goCmdStr)

	// Convert Go string to Java
	cResponse := C.CString(response)
	defer C.free(unsafe.Pointer(cResponse))

	return C.jni_new_string(env, cResponse)
}

// Helper functions

func sendStateChange(state string, jsonData string) {
	cState := C.CString(state)
	cJSON := C.CString(jsonData)
	defer C.free(unsafe.Pointer(cState))
	defer C.free(unsafe.Pointer(cJSON))

	C.jni_state_callback(cState, cJSON)
}

func logMessage(message string) {
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))

	C.jni_log_callback(cMessage)
}

// runClientWithContext runs the client with a cancelable context
// This is a wrapper around the existing runClient() function
func runClientWithContext(ctx context.Context, args []string) error {
	// Parse config from args
	cfg, err := parseClientArgs(args)
	if err != nil {
		return fmt.Errorf("failed to parse args: %w", err)
	}

	// Set Android mode
	cfg.AndroidMode = true

	// Use TUN fd from JNI if set
	tunFdLock.Lock()
	if tunFd > 0 {
		cfg.TunFd = tunFd
		logMessage(fmt.Sprintf("Using TUN fd from JNI: %d", tunFd))
	}
	tunFdLock.Unlock()

	// Run client with context
	return client.RunWithContext(ctx, cfg)
}

// parseClientArgs parses command line args into client.Config
func parseClientArgs(args []string) (*client.Config, error) {
	cfg := &client.Config{
		AndroidMode: true,
		// TUN is opt-in via -tun. The app's TUN path always passes -tun; proxy mode
		// passes -listen instead and must NOT be forced into TUN (it has no tun-fd,
		// so a forced TUN setup fails and proxy mode never starts).
		TunMode: false,
		// 1500 left no room for tunnel encapsulation (4-byte length frame + the
		// strategy's TLS/WebSocket/etc. overhead), so inner TCP segments clamped
		// to MTU-40 produced outer packets larger than the underlying path MTU.
		// On Android that meant fragmentation / PMTUD blackholes and badly
		// degraded download throughput (issue #27). 1280 (the IPv6 minimum, same
		// as tun.DefaultMTU) leaves a safe margin for all encapsulation. The app
		// can still override via -tun-mtu.
		TunMTU: 1280,
	}

	// Shaper preset/seed are captured during the scan and applied after the loop
	// so a -shaper-seed in any position still feeds the same -shaper build.
	var (
		shaperName string
		shaperSeed int64
	)

	// Parse flags from args (simple parser, doesn't use flag package)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			if i+1 < len(args) {
				cfg.ServerAddr = args[i+1]
				i++
			}
		case "-secret":
			if i+1 < len(args) {
				cfg.Secret = args[i+1]
				i++
			}
		// Proxy mode: SOCKS5/HTTP listener (no -tun). Without this the app's
		// proxy connection mode silently lost its listen address.
		case "-listen":
			if i+1 < len(args) {
				cfg.ListenAddr = args[i+1]
				i++
			}
		case "-http-listen":
			if i+1 < len(args) {
				cfg.HTTPListenAddr = args[i+1]
				i++
			}
		case "-tun-ip":
			if i+1 < len(args) {
				cfg.TunIP = args[i+1]
				i++
			}
		case "-tun-peer-ip":
			if i+1 < len(args) {
				cfg.TunPeerIP = args[i+1]
				i++
			}
		case "-tun-mtu":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &cfg.TunMTU)
				i++
			}
		case "-control-socket":
			if i+1 < len(args) {
				cfg.ControlSocket = args[i+1]
				i++
			}
		case "-protect-path":
			if i+1 < len(args) {
				cfg.ProtectPath = args[i+1]
				i++
			}
		case "-strategy":
			if i+1 < len(args) {
				cfg.StrategyName = args[i+1]
				i++
			}
		// -cover is the canonical flag (matches CLI -cover and what the app sends).
		// -cover-host is kept as a legacy alias.
		case "-cover", "-cover-host":
			if i+1 < len(args) {
				cfg.CoverHost = args[i+1]
				i++
			}
		case "-debug":
			cfg.Debug = true
		case "-tun":
			cfg.TunMode = true
		case "-android":
			cfg.AndroidMode = true

		// QUIC transport
		case "-quic":
			cfg.QUICEnabled = true
		case "-quic-port":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.QUICPort = v
				} else {
					log.Warn("parseClientArgs: invalid -quic-port value %q: %v", args[i+1], err)
				}
				i++
			}
		case "-quic-sni-frag":
			cfg.QUICSNIFragEnabled = true

		// RTT masking
		case "-rtt-masking":
			cfg.RTTMaskingEnabled = true
		case "-rtt-profile":
			if i+1 < len(args) {
				cfg.RTTProfile = args[i+1]
				i++
			}

		// Mid-session fallback
		case "-fallback":
			cfg.EnableFallback = true

		// Traffic shaper (built identically to CLI runClient via applyShaperFlag)
		case "-shaper":
			if i+1 < len(args) {
				shaperName = args[i+1]
				i++
			}
		case "-shaper-seed":
			if i+1 < len(args) {
				if v, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					shaperSeed = v
				} else {
					log.Warn("parseClientArgs: invalid -shaper-seed value %q: %v", args[i+1], err)
				}
				i++
			}

		// ECH (Encrypted Client Hello)
		case "-ech":
			cfg.ECHEnabled = true
		case "-ech-config":
			if i+1 < len(args) {
				cfg.ECHConfigB64 = args[i+1]
				i++
			}
		case "-ech-public-name":
			if i+1 < len(args) {
				cfg.ECHPublicName = args[i+1]
				i++
			}

		// IPv6 transport
		case "-server-v6":
			if i+1 < len(args) {
				cfg.ServerAddrV6 = args[i+1]
				i++
			}
		case "-prefer-ipv6":
			if i+1 < len(args) {
				if v, err := strconv.ParseBool(args[i+1]); err == nil {
					cfg.PreferIPv6 = v
				} else {
					log.Warn("parseClientArgs: invalid -prefer-ipv6 value %q: %v", args[i+1], err)
				}
				i++
			}
		case "-fallback-v4":
			if i+1 < len(args) {
				if v, err := strconv.ParseBool(args[i+1]); err == nil {
					cfg.FallbackToV4 = v
				} else {
					log.Warn("parseClientArgs: invalid -fallback-v4 value %q: %v", args[i+1], err)
				}
				i++
			}

		default:
			// No more silent drops: log every unrecognized token so flag
			// contract drift between the app and the core is visible.
			log.Warn("parseClientArgs: ignoring unknown flag %q", args[i])
		}
	}

	// Build the shaper exactly like the CLI path (runClient -> applyShaperFlag):
	// presets.ByName(name, seed) for cfg.Shaper and presets.IDForName(name) for
	// cfg.ShaperID, including the unknown-preset error.
	if shaperName != "" {
		if err := applyShaperFlag(cfg, shaperName, shaperSeed); err != nil {
			return nil, err
		}
	}

	// Validate required fields
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("missing required flag: -server")
	}

	return cfg, nil
}
