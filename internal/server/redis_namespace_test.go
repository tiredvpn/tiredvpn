package server

import "testing"

func TestNormalizeRedisPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty falls back to default", "", DefaultRedisPrefix},
		{"default is unchanged", "tiredvpn:", "tiredvpn:"},
		{"colon appended", "relay", "relay:"},
		{"nested namespace kept", "ams:relay:", "ams:relay:"},
		{"nested namespace gets colon", "ams:relay", "ams:relay:"},
		{"lone colon is a valid namespace", ":", ":"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeRedisPrefix(tt.input); got != tt.want {
				t.Errorf("NormalizeRedisPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateRedisDB(t *testing.T) {
	tests := []struct {
		db      int
		wantErr bool
	}{
		{0, false},
		{1, false},
		{15, false},
		{16, true},
		{-1, true},
	}

	for _, tt := range tests {
		err := ValidateRedisDB(tt.db)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateRedisDB(%d) error = %v, wantErr %v", tt.db, err, tt.wantErr)
		}
	}
}

// TestRedisStoreKeys pins the key layout: the zero-value db and the default
// prefix must reproduce the pre-existing keys byte for byte, and a configured
// namespace must show up in every key.
func TestRedisStoreKeys(t *testing.T) {
	tests := []struct {
		name        string
		db          int
		prefix      string
		wantClient  string
		wantStats   string
		wantVersion string
		wantPattern string
		wantChannel string
	}{
		{
			name:        "defaults match legacy layout",
			db:          0,
			prefix:      DefaultRedisPrefix,
			wantClient:  "tiredvpn:clients:abc",
			wantStats:   "tiredvpn:stats:abc",
			wantVersion: "tiredvpn:version",
			wantPattern: "tiredvpn:clients:*",
			wantChannel: "__keyspace@0__:tiredvpn:clients:*",
		},
		{
			name:        "custom db and prefix",
			db:          3,
			prefix:      "relay:",
			wantClient:  "relay:clients:abc",
			wantStats:   "relay:stats:abc",
			wantVersion: "relay:version",
			wantPattern: "relay:clients:*",
			wantChannel: "__keyspace@3__:relay:clients:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RedisStore{db: tt.db, prefix: tt.prefix}
			if got := r.clientKey("abc"); got != tt.wantClient {
				t.Errorf("clientKey = %q, want %q", got, tt.wantClient)
			}
			if got := r.statsKey("abc"); got != tt.wantStats {
				t.Errorf("statsKey = %q, want %q", got, tt.wantStats)
			}
			if got := r.versionKey(); got != tt.wantVersion {
				t.Errorf("versionKey = %q, want %q", got, tt.wantVersion)
			}
			if got := r.clientKeyPattern(); got != tt.wantPattern {
				t.Errorf("clientKeyPattern = %q, want %q", got, tt.wantPattern)
			}
			if got := r.keyspaceChannelPattern(); got != tt.wantChannel {
				t.Errorf("keyspaceChannelPattern = %q, want %q", got, tt.wantChannel)
			}
		})
	}
}

// TestSecretIndexKeyNamespaced guards the secret index, which is the lookup a
// second instance would otherwise share.
func TestSecretIndexKeyNamespaced(t *testing.T) {
	def := (&RedisStore{prefix: DefaultRedisPrefix}).secretIndexKey("s3cret")
	custom := (&RedisStore{prefix: "relay:"}).secretIndexKey("s3cret")

	if def == custom {
		t.Fatalf("secret index key is not namespaced: both stores produced %q", def)
	}
	if want := "tiredvpn:secrets:"; def[:len(want)] != want {
		t.Errorf("default secret index key = %q, want prefix %q", def, want)
	}
	if want := "relay:secrets:"; custom[:len(want)] != want {
		t.Errorf("custom secret index key = %q, want prefix %q", custom, want)
	}
}

func TestClientIDFromKeyspaceChannel(t *testing.T) {
	tests := []struct {
		name    string
		db      int
		prefix  string
		channel string
		want    string
	}{
		{
			name:    "default namespace",
			db:      0,
			prefix:  DefaultRedisPrefix,
			channel: "__keyspace@0__:tiredvpn:clients:2f1a-uuid",
			want:    "2f1a-uuid",
		},
		{
			name:    "custom namespace",
			db:      2,
			prefix:  "relay:",
			channel: "__keyspace@2__:relay:clients:2f1a-uuid",
			want:    "2f1a-uuid",
		},
		{
			name:    "other db is ignored",
			db:      2,
			prefix:  "relay:",
			channel: "__keyspace@0__:relay:clients:2f1a-uuid",
			want:    "",
		},
		{
			name:    "other prefix is ignored",
			db:      0,
			prefix:  "relay:",
			channel: "__keyspace@0__:tiredvpn:clients:2f1a-uuid",
			want:    "",
		},
		{
			name:    "non-client key is ignored",
			db:      0,
			prefix:  DefaultRedisPrefix,
			channel: "__keyspace@0__:tiredvpn:stats:2f1a-uuid",
			want:    "",
		},
		{
			name:    "nested namespace keeps full id",
			db:      0,
			prefix:  "ams:relay:",
			channel: "__keyspace@0__:ams:relay:clients:2f1a-uuid",
			want:    "2f1a-uuid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RedisStore{db: tt.db, prefix: tt.prefix}
			if got := r.clientIDFromKeyspaceChannel(tt.channel); got != tt.want {
				t.Errorf("clientIDFromKeyspaceChannel(%q) = %q, want %q", tt.channel, got, tt.want)
			}
		})
	}
}

// TestIPPoolKeysNamespaced covers the other half of the isolation problem: two
// instances on one Redis must not share the lease namespace, or they hand out
// the same tunnel IPs.
func TestIPPoolKeysNamespaced(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		wantLease   string
		wantClient  string
		wantPattern string
	}{
		{
			name:        "empty prefix keeps legacy keys",
			prefix:      "",
			wantLease:   "tiredvpn:ippool:10.8.0.2",
			wantClient:  "tiredvpn:ippool:client:cid",
			wantPattern: "tiredvpn:ippool:10.*",
		},
		{
			name:        "custom prefix is normalized and applied",
			prefix:      "relay",
			wantLease:   "relay:ippool:10.8.0.2",
			wantClient:  "relay:ippool:client:cid",
			wantPattern: "relay:ippool:10.*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewIPPool(IPPoolConfig{
				Network:   "10.8.0.0/24",
				ServerIP:  "10.8.0.1",
				KeyPrefix: tt.prefix,
			}, nil)
			if err != nil {
				t.Fatalf("NewIPPool: %v", err)
			}
			if got := p.redisKey("10.8.0.2"); got != tt.wantLease {
				t.Errorf("redisKey = %q, want %q", got, tt.wantLease)
			}
			if got := p.redisClientKey("cid"); got != tt.wantClient {
				t.Errorf("redisClientKey = %q, want %q", got, tt.wantClient)
			}
			if got := p.leaseKeyPattern(); got != tt.wantPattern {
				t.Errorf("leaseKeyPattern = %q, want %q", got, tt.wantPattern)
			}
		})
	}
}
