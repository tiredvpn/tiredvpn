package main

import (
	"flag"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/server"
)

// parseServerFlags registers the server flag set and parses args, returning the
// resulting Config and the flag set (needed to tell "explicitly set" apart from
// "left at default").
func parseServerFlags(t *testing.T, args []string) (*server.Config, *flag.FlagSet) {
	t.Helper()
	cfg := &server.Config{}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	registerServerFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return cfg, fs
}

// TestRedisNamespaceDefaults pins backward compatibility: without any of the
// new flags or env vars the server must land on db 0 / "tiredvpn:".
func TestRedisNamespaceDefaults(t *testing.T) {
	cfg, fs := parseServerFlags(t, nil)

	if err := applyRedisNamespaceEnv(cfg, fs); err != nil {
		t.Fatalf("applyRedisNamespaceEnv: %v", err)
	}
	if cfg.RedisDB != 0 {
		t.Errorf("RedisDB = %d, want 0", cfg.RedisDB)
	}
	if cfg.RedisPrefix != server.DefaultRedisPrefix {
		t.Errorf("RedisPrefix = %q, want %q", cfg.RedisPrefix, server.DefaultRedisPrefix)
	}
}

func TestRedisNamespaceFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantDB     int
		wantPrefix string
	}{
		{"db only", []string{"-redis-db", "3"}, 3, server.DefaultRedisPrefix},
		{"prefix only", []string{"-redis-prefix", "relay:"}, 0, "relay:"},
		{"prefix normalized", []string{"-redis-prefix", "relay"}, 0, "relay:"},
		{"empty prefix falls back", []string{"-redis-prefix", ""}, 0, server.DefaultRedisPrefix},
		{"both", []string{"-redis-db", "15", "-redis-prefix", "usa2"}, 15, "usa2:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, fs := parseServerFlags(t, tt.args)
			if err := applyRedisNamespaceEnv(cfg, fs); err != nil {
				t.Fatalf("applyRedisNamespaceEnv: %v", err)
			}
			if cfg.RedisDB != tt.wantDB {
				t.Errorf("RedisDB = %d, want %d", cfg.RedisDB, tt.wantDB)
			}
			if cfg.RedisPrefix != tt.wantPrefix {
				t.Errorf("RedisPrefix = %q, want %q", cfg.RedisPrefix, tt.wantPrefix)
			}
		})
	}
}

func TestRedisNamespaceInvalidDB(t *testing.T) {
	for _, args := range [][]string{{"-redis-db", "16"}, {"-redis-db", "-1"}} {
		cfg, fs := parseServerFlags(t, args)
		if err := applyRedisNamespaceEnv(cfg, fs); err == nil {
			t.Errorf("applyRedisNamespaceEnv(%v) = nil error, want out-of-range error", args)
		}
	}
}

// TestRedisNamespaceEnvFallback checks the flag > env > default order, matching
// how -api-token resolves TIREDVPN_API_TOKEN.
func TestRedisNamespaceEnvFallback(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		envDB      string
		envPrefix  string
		wantDB     int
		wantPrefix string
		wantErr    bool
	}{
		{
			name:       "env used when flags absent",
			envDB:      "2",
			envPrefix:  "ams-relay",
			wantDB:     2,
			wantPrefix: "ams-relay:",
		},
		{
			name:       "flags win over env",
			args:       []string{"-redis-db", "4", "-redis-prefix", "flagged:"},
			envDB:      "2",
			envPrefix:  "ams-relay:",
			wantDB:     4,
			wantPrefix: "flagged:",
		},
		{
			name:       "explicit db 0 wins over env",
			args:       []string{"-redis-db", "0"},
			envDB:      "7",
			wantDB:     0,
			wantPrefix: server.DefaultRedisPrefix,
		},
		{
			name:    "non-numeric env db is an error",
			envDB:   "nope",
			wantErr: true,
		},
		{
			name:    "out-of-range env db is an error",
			envDB:   "42",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TIREDVPN_REDIS_DB", tt.envDB)
			t.Setenv("TIREDVPN_REDIS_PREFIX", tt.envPrefix)

			cfg, fs := parseServerFlags(t, tt.args)
			err := applyRedisNamespaceEnv(cfg, fs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("applyRedisNamespaceEnv = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("applyRedisNamespaceEnv: %v", err)
			}
			if cfg.RedisDB != tt.wantDB {
				t.Errorf("RedisDB = %d, want %d", cfg.RedisDB, tt.wantDB)
			}
			if cfg.RedisPrefix != tt.wantPrefix {
				t.Errorf("RedisPrefix = %q, want %q", cfg.RedisPrefix, tt.wantPrefix)
			}
		})
	}
}
