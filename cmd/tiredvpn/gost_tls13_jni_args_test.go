package main

import (
	"strings"
	"testing"
)

func TestParseClientArgsGOSTTLS13Flags(t *testing.T) {
	pin := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	args := []string{
		"-server", "203.0.113.10:12443",
		"-secret", "client-secret",
		"-strategy", "gost_tls13_gosuslugi",
		"-gost-tls13-pin", pin,
		"-gost-tls13-port", "12444",
	}
	cfg, err := parseClientArgs(args)
	if err != nil {
		t.Fatalf("parseClientArgs: %v", err)
	}
	if cfg.StrategyName != "gost_tls13_gosuslugi" || cfg.GOSTTLSPin != pin || cfg.GOSTTLSPort != 12444 {
		t.Fatalf("GOST config not parsed: strategy=%q pin=%q port=%d", cfg.StrategyName, cfg.GOSTTLSPin, cfg.GOSTTLSPort)
	}
	line := jniStartLogLine(args)
	if strings.Contains(line, pin) {
		t.Fatalf("JNI start log exposed certificate pin: %s", line)
	}
	if !strings.Contains(line, "-gost-tls13-pin ***") || !strings.Contains(line, "-gost-tls13-port 12444") {
		t.Fatalf("JNI start log should redact pin and retain port: %s", line)
	}
}
