# Client Reference

Complete reference for `tiredvpn client`.

## Usage

```
tiredvpn client [options]
```

## Modes

### SOCKS5 / HTTP proxy mode (default)

Starts a local proxy server. Applications connect to it explicitly.

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -listen 127.0.0.1:1080
```

The proxy auto-detects SOCKS5 vs HTTP based on the first byte of each connection. Use `-http-listen` to run both on separate ports.

### TUN mode (full VPN)

Creates a `tiredvpn0` TUN interface and installs system routes. All traffic matching the routes goes through the VPN. Requires `root` or `CAP_NET_ADMIN`.

```bash
sudo tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -tun \
  -tun-routes 0.0.0.0/0
```

## Flag Reference

### CORE OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | | **[required]** Remote server address (`host:port`) |
| `-secret` | | **[required]** Shared secret for authentication |
| `-listen` | `127.0.0.1:1080` | Local proxy address (SOCKS5/HTTP auto-detect) |
| `-http-listen` | | Separate HTTP proxy address (optional) |
| `-strategy` | | Force a specific strategy; skips auto-selection |
| `-list` | `false` | Print available strategies and exit |
| `-debug` | `false` | Enable verbose debug logging |

To see all available strategy IDs:

```bash
tiredvpn client -list
```

### IPv6 TRANSPORT

| Flag | Default | Description |
|------|---------|-------------|
| `-server-v6` | | Server IPv6 address (e.g., `[2001:db8::1]:995`) |
| `-prefer-ipv6` | `true` | Use IPv6 transport when available |
| `-fallback-v4` | `true` | Fall back to IPv4 if IPv6 transport fails |

When both `-server` and `-server-v6` are provided, the client uses IPv6 by default and falls back to IPv4 automatically.

### TUN MODE (Full VPN)

| Flag | Default | Description |
|------|---------|-------------|
| `-tun` | `false` | Enable TUN mode |
| `-tun-name` | `tiredvpn0` | TUN device name |
| `-tun-ip` | `10.8.0.2` | Local TUN IP address |
| `-tun-peer-ip` | `10.8.0.1` | Remote TUN peer IP (server side) |
| `-tun-mtu` | `1280` | TUN device MTU |
| `-tun-routes` | | Comma-separated CIDRs to route through VPN |
| `-tun-fd` | `-1` | Use an existing TUN file descriptor (Android VpnService) |

`-tun-routes 0.0.0.0/0` routes all traffic. For split tunnel, list specific CIDRs:

```bash
-tun-routes 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

### ANDROID INTEGRATION

| Flag | Default | Description |
|------|---------|-------------|
| `-android` | `false` | Android mode (disables `os/exec`, ICMP checks) |
| `-protect-path` | | Unix socket path for Android `VpnService.protect()` |
| `-control-socket` | | Control socket for Android 2-phase connect protocol |

See the Android SDK integration guide for how to use these. The JNI entry points are in `cmd/tiredvpn/jni.go`.

### PORT HOPPING

| Flag | Default | Description |
|------|---------|-------------|
| `-port-hop` | `false` | Enable port hopping |
| `-port-hop-start` | `47000` | Port range start |
| `-port-hop-end` | `65535` | Port range end |
| `-port-hop-interval` | `1m` | How often to hop (with ±30s jitter) |
| `-port-hop-strategy` | `random` | `random`, `sequential`, or `fibonacci` |
| `-port-hop-seed` | | Seed for deterministic hopping (must match server) |

Port hopping rotates to a new server port at each interval. The server must be listening on a matching port range (`-port-range`). For deterministic hopping both ends must use the same `-port-hop-seed`.

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -port-hop \
  -port-hop-start 47000 \
  -port-hop-end 47100 \
  -port-hop-interval 1m \
  -port-hop-strategy random
```

### ADVANCED EVASION

| Flag | Default | Description |
|------|---------|-------------|
| `-quic` | `false` | Enable QUIC transport (UDP, highest priority) |
| `-quic-port` | `443` | Server QUIC port |
| `-quic-sni-frag` | `false` | Fragment QUIC Initial SNI (GFW bypass) |
| `-ech` | `false` | Enable Encrypted Client Hello (hides SNI) |
| `-ech-config` | | ECHConfigList in base64 (from server) |
| `-ech-public-name` | `cloudflare-ech.com` | Outer SNI visible to network when using ECH |
| `-pq` | `false` | Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65) |
| `-pq-server-key` | | Server's ML-KEM public key in base64 |
| `-rtt-masking` | `false` | Enable RTT masking (hides proxy timing signature) |
| `-rtt-profile` | `moscow-yandex` | RTT profile to emulate (see table below) |
| `-cover` | `api.googleapis.com` | Cover host for traffic mimicry (SNI / Host header) |

#### RTT profiles

| Profile | Emulates |
|---------|----------|
| `moscow-yandex` | Moscow–Yandex CDN latency |
| `moscow-vk` | Moscow–VK CDN latency |
| `regional-russia` | Russia regional ISP latency |
| `siberia` | Siberian ISP latency |
| `cdn` | Generic CDN latency |
| `beijing-baidu` | Beijing–Baidu latency (China) |
| `tehran-aparat` | Tehran–Aparat latency (Iran) |

RTT masking adds artificial delay jitter that matches the chosen profile, making the VPN connection statistically indistinguishable from regular browsing to the chosen service.

#### ECH (Encrypted Client Hello)

ECH hides the SNI in the TLS handshake. The outer TLS handshake shows `-ech-public-name` while the real server name is encrypted.

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -ech \
  -ech-public-name cloudflare-ech.com
```

#### Post-quantum cryptography

Enables ML-KEM-768 key encapsulation and ML-DSA-65 signatures for the REALITY handshake:

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -pq \
  -pq-server-key <base64-encoded-mlkem-pubkey>
```

### ADAPTIVE STRATEGY

| Flag | Default | Description |
|------|---------|-------------|
| `-reprobe-interval` | `5m` | How often to re-test all strategies |
| `-circuit-threshold` | `3` | Number of failures before circuit opens (disables strategy) |
| `-circuit-reset` | `5m` | Time before a tripped circuit tries again (half-open) |
| `-fallback` | `true` | Switch strategies mid-session if connection degrades |

The adaptive engine runs continuously in the background:
1. Probes all available strategies in parallel
2. Ranks by success rate and latency
3. Uses the best strategy; monitors it with a circuit breaker
4. On failure, falls back to the next-best; re-probes after `-reprobe-interval`

Disable fallback with `-fallback=false` if you want to stay on the forced `-strategy` even if it degrades.

### BENCHMARKING

| Flag | Default | Description |
|------|---------|-------------|
| `-benchmark` | `false` | Test all strategies: latency only |
| `-benchmark-full` | `false` | Full benchmark: HTTP, latency, throughput, IP change |
| `-benchmark-all` | `false` | Exhaustive: all strategies × all RTT profiles (78 combinations) |

```bash
# Quick latency test
tiredvpn client -server host:443 -secret <s> -benchmark

# Full performance test
tiredvpn client -server host:443 -secret <s> -benchmark-full

# Exhaustive (takes several minutes)
tiredvpn client -server host:443 -secret <s> -benchmark-all
```

Benchmark results show per-strategy latency, success rate, and throughput. Use these to choose the right `-strategy` for your network.

### MONITORING

| Flag | Default | Description |
|------|---------|-------------|
| `-api-addr` | | Enable metrics/API HTTP endpoint (e.g., `:8080`) |
| `-pprof` | | Enable pprof profiling (e.g., `:6060`) |
| `-version` | | Print version and exit |

See [monitoring.md](monitoring.md) for Prometheus metrics details.

## Configuration Examples

### Russia (TSPU bypass)

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -quic \
  -quic-sni-frag \
  -rtt-masking \
  -rtt-profile moscow-yandex \
  -cover api.googleapis.com \
  -listen 127.0.0.1:1080
```

### China (GFW bypass)

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -quic \
  -quic-sni-frag \
  -ech \
  -pq \
  -port-hop \
  -rtt-masking \
  -rtt-profile beijing-baidu \
  -listen 127.0.0.1:1080
```

### Iran

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -strategy http2_stego \
  -rtt-masking \
  -rtt-profile tehran-aparat \
  -listen 127.0.0.1:1080
```

### Maximum stealth (all evasion enabled)

```bash
tiredvpn client \
  -server your-server.com:443 \
  -server-v6 [2001:db8::1]:995 \
  -prefer-ipv6 \
  -secret <secret> \
  -quic \
  -quic-sni-frag \
  -ech \
  -pq \
  -port-hop \
  -rtt-masking \
  -rtt-profile moscow-yandex \
  -listen 127.0.0.1:1080
```

### Full VPN with split routing

```bash
sudo tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -tun \
  -tun-name tiredvpn0 \
  -tun-ip 10.8.0.2 \
  -tun-peer-ip 10.8.0.1 \
  -tun-mtu 1280 \
  -tun-routes 0.0.0.0/0
```

### With monitoring

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -listen 127.0.0.1:1080 \
  -api-addr :9090 \
  -pprof :6061
```

Metrics at `http://localhost:9090/metrics`, pprof at `http://localhost:6061/debug/pprof/`.
