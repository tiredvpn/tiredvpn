package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

const (
	cfgErrSecret = "PLACEHOLDER-SECRET-0451"
	cfgErrAddr   = "203.0.113.77"
)

// A pool config with a typo on the line after a secret, the way a -config file
// passed by the app or by a desktop unit could break.
const cfgErrPool = "[[servers]]\naddress = \"" + cfgErrAddr + "\"\nsecret = \"" + cfgErrSecret + "\"\nport = 9x\n"

func assertCfgErrClean(t *testing.T, where string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the broken config was accepted", where)
	}
	msg := err.Error()
	for _, v := range []string{cfgErrSecret, cfgErrAddr} {
		if strings.Contains(msg, v) {
			t.Errorf("%s: error holds %q: %s", where, v, msg)
		}
	}
	// Positive control: this is the decode error, with its position.
	if !strings.Contains(msg, "line 4, column ") || !strings.Contains(msg, "strings must be quoted") {
		t.Errorf("%s: not the decode error with its position: %s", where, msg)
	}
}

// TestConfigDecodeErrorOnEveryPath: every caller of the loader hands the
// error on as text - the JNI parser into "Client error" and the error state,
// the desktop client and server to stderr.
func TestConfigDecodeErrorOnEveryPath(t *testing.T) {
	p := writeClientTOML(t, cfgErrPool)

	_, err := parseClientArgs([]string{"-config", p})
	assertCfgErrClean(t, "JNI parseClientArgs", err)
	// jni_android.go sends fmt.Sprintf(`{"error":"%s"}`, "Client error: "+...)
	// to onStateChange. go-toml's own text spanned several lines and broke
	// that JSON; the one-line text keeps it valid.
	if err != nil {
		state := fmt.Sprintf(`{"error":"%s"}`, "Client error: failed to parse args: "+err.Error())
		if !json.Valid([]byte(state)) {
			t.Errorf("error state is not valid JSON: %s", state)
		}
	}

	assertCfgErrClean(t, "desktop client", applyClientTOMLConfig(&client.Config{}, p, clientFlagSetForTOML()))
	assertCfgErrClean(t, "desktop server", applyServerTOMLConfig(&server.Config{}, p, nil))
}
