# DPI Bypass Strategies

TiredVPN implements 20+ DPI evasion strategies. The adaptive strategy engine automatically selects and maintains the best one for your network conditions.

## Strategy List

| ID | Name | Transport | Evasion Technique | Priority |
|----|------|-----------|-------------------|----------|
| `quic_salamander` | QUIC Salamander | QUIC/UDP | QUIC with Salamander obfuscation padding | High |
| `quic` | QUIC Tunnel | QUIC/UDP | QUIC with draft-29 version spoofing | High |
| `reality` | REALITY Protocol | TLS/TCP | X25519 handshake; impersonates real websites | Medium |
| `http2_stego` | HTTP/2 Steganography | HTTP/2 | Data hidden in legitimate HTTP/2 frames | Medium |
| `websocket_padded` | WebSocket Salamander | WebSocket | WebSocket + Salamander obfuscation | Medium |
| `http_polling` | HTTP Polling | HTTP/1.1 | Short-lived poll requests (meek-style) | Medium |
| `morph_yandex` | Traffic Morphing (Yandex) | TLS/TCP | Traffic shaped to match Yandex video | Low |
| `morph_vk` | Traffic Morphing (VK) | TLS/TCP | Traffic shaped to match VK video | Low |
| `confusion_dns` | Protocol Confusion (DNS) | TLS/TCP | Packets appear as DNS-over-TLS | Low |
| `confusion_http` | Protocol Confusion (HTTP) | TLS/TCP | Packets appear as plain HTTP traffic | Low |
| `confusion_ssh` | Protocol Confusion (SSH) | TLS/TCP | Packets appear as SSH traffic | Low |
| `confusion_smtp` | Protocol Confusion (SMTP) | TLS/TCP | Packets appear as SMTP over TLS | Low |
| `geneva_russia` | Geneva (Russia) | TCP | TSPU-specific packet manipulation rules | Variable |
| `geneva_china` | Geneva (China) | TCP | GFW-specific packet manipulation rules | Variable |
| `geneva_iran` | Geneva (Iran) | TCP | Iran-specific packet manipulation rules | Variable |
| `antiprobe` | Anti-Probe | TLS/TCP | Serves real website; reveals tunnel only to auth clients | Medium |
| `state_exhaustion` | State Exhaustion | TCP | Floods DPI state table with decoy streams | Low |
| `mesh_relay` | Mesh Relay | TCP/UDP | Routes through relay nodes in lighter-filtered regions | Variable |
| `ssh_camouflage` | SSH Camouflage | TCP | Masquerades as SSH session; correct banner + KEXINIT, then data in SSH packet framing (type 0xFF); HMAC-SHA256 auth with 300s time window | 28 |
| `imap_camouflage` | IMAP Camouflage | TCP | Masquerades as IMAP mailbox sync; data in FETCH responses and APPEND literals; HMAC-SHA256 auth | 29 |
| `icmp_tunnel` | ICMP Tunnel | ICMP | Backup tunnel over ICMP Echo/Reply | Emergency |

To see the full list on your binary:

```bash
tiredvpn client -list
```

The Geneva strategy ships with four country rule-sets (`russia`, `china`, `iran`, `turkey`), but only `geneva_russia`, `geneva_china`, and `geneva_iran` are registered as strategy IDs by default. The `turkey` rule-set exists in the engine but is not exposed as a registered ID - using it requires a code change to register `NewGenevaStrategy(m, secret, "turkey")`.

## How the Adaptive Engine Works

### 1. Initial probing

When the client starts (or after a re-probe interval), it probes all non-tripped strategies in parallel:

- Each strategy makes a test connection to the server
- Latency and success are recorded
- Strategies are ranked by `score = success_rate × (1 / latency)`

### 2. Strategy selection

The highest-scoring strategy is activated. If multiple strategies have similar scores, QUIC-based strategies are preferred.

### 3. Circuit breakers

Each strategy has its own circuit breaker:

- **Closed** (normal): strategy is available
- **Open** (tripped): strategy is disabled after `-circuit-threshold` consecutive failures (default: 3)
- **Half-open** (testing): after `-circuit-reset` (default: 5m), one test connection is allowed; if successful, circuit closes; if not, it stays open

### 4. Mid-session fallback

If the active strategy fails mid-session and `-fallback=true` (default), the client:

1. Activates the next-best strategy immediately
2. Re-establishes in-flight connections on the new strategy
3. Logs the switch (visible with `-debug`)

This means a brief pause (typically < 1 second) rather than a dropped connection.

### 5. Periodic re-probing

Every `-reprobe-interval` (default: 5m), the engine re-probes all strategies including tripped ones. A previously blocked strategy may have become available again.

An emergency re-probe is triggered when all active strategies fail simultaneously (network loss or total block).

## Choosing a Strategy

### Automatic (recommended)

Leave `-strategy` unset. The engine handles everything.

```bash
tiredvpn client -server host:443 -secret <s> -listen 127.0.0.1:1080
```

### Forced strategy

To force a specific strategy (e.g., for debugging or benchmarking):

```bash
tiredvpn client -server host:443 -secret <s> -strategy quic_salamander
```

### By censorship environment

**Russia (TSPU)**

TSPU blocks QUIC and common VPN protocols. Best options:
- `quic_salamander` with `-quic-sni-frag` (SNI fragmentation defeats TSPU SNI detection)
- `http2_stego` (data hidden in HTTP/2 frames, very hard to block)
- `geneva_russia` (specifically tuned for TSPU rules)

```bash
tiredvpn client \
  -server host:443 \
  -secret <s> \
  -quic -quic-sni-frag \
  -rtt-masking -rtt-profile moscow-yandex
```

**China (GFW)**

GFW uses deep statistical analysis. Best options:
- `quic_salamander` (Salamander padding defeats GFW entropy analysis)
- `reality` (impersonates a real website with authentic TLS fingerprints)
- `http2_stego` with ECH

```bash
tiredvpn client \
  -server host:443 \
  -secret <s> \
  -quic -quic-sni-frag \
  -ech -pq \
  -rtt-masking -rtt-profile beijing-baidu
```

**Iran**

Iran blocks on HTTP/HTTPS inspection. Best options:
- `http2_stego` (legitimate-looking HTTP/2)
- `morph_yandex` or `morph_vk` (mimics video streaming)

```bash
tiredvpn client \
  -server host:443 \
  -secret <s> \
  -strategy http2_stego \
  -rtt-masking -rtt-profile tehran-aparat
```

**Turkey**

Turkey uses SNI-based blocking. Best options:
- `reality` (no identifiable SNI)
- `quic_salamander` with ECH

## Benchmarking

Run benchmarks to find the best strategy for your specific network path:

```bash
# Quick latency test (all strategies, ~30 seconds)
tiredvpn client -server host:443 -secret <s> -benchmark

# Full benchmark: latency + throughput + IP change (~2 minutes)
tiredvpn client -server host:443 -secret <s> -benchmark-full

# Exhaustive: all strategies × all RTT profiles (78 combinations, ~10 minutes)
tiredvpn client -server host:443 -secret <s> -benchmark-all
```

Sample output (success rate depends on the censor and is not shown - run on your own network path to get meaningful numbers):

```
Strategy Benchmark Results:
┌─────────────────────┬──────────┬───────────┐
│ Strategy            │ Latency  │ Throughput│
├─────────────────────┼──────────┼───────────┤
│ quic_salamander     │  45ms    │  98 Mbps  │
│ quic                │  48ms    │  95 Mbps  │
│ http2_stego         │  52ms    │  87 Mbps  │
│ reality             │  55ms    │  89 Mbps  │
│ websocket_padded    │  61ms    │  72 Mbps  │
│ icmp_tunnel         │ 120ms    │  31 Mbps  │
└─────────────────────┴──────────┴───────────┘
```

## Strategy Details

### QUIC Salamander

Uses the QUIC protocol over UDP with [Salamander](https://arxiv.org/abs/2407.02996) obfuscation. Salamander pads QUIC Initial packets to remove the statistical fingerprint that DPI systems use to identify QUIC. Three padding levels: Conservative, Balanced, Aggressive.

Best against: TSPU (Russia), QUIC-blocking firewalls.

### REALITY Protocol

Implements a custom TLS extension that performs an X25519 key exchange with an HMAC-based auth token. To unauthenticated observers, the server looks like a real HTTPS site. Uses uTLS to mimic genuine browser TLS fingerprints (Chrome, Firefox, iOS).

Best against: fingerprint-based blocking, GFW active probing.

### HTTP/2 Steganography

Encodes tunnel data inside legitimate HTTP/2 DATA and HEADERS frames, mimicking the NaiveProxy traffic pattern. The traffic is indistinguishable from normal browser-to-CDN traffic.

Best against: Iran's HTTP inspection, sophisticated DPI.

### Geneva Engine

Integrates the [Geneva](https://geneva.cs.umd.edu) censorship circumvention engine. Applies country-specific packet manipulation rules (fragment, duplicate, send out-of-order) that have been shown to confuse DPI implementations in specific countries.

On Linux with `CAP_NET_ADMIN`, Geneva uses NFQUEUE to inject raw packets directly into the network stack. On non-Linux systems and without the required capability, it falls back to byte-level fragmentation of the TLS ClientHello.

### SSH Camouflage

Masquerades the tunnel as a real SSH session. The client sends a correct SSH banner (`SSH-2.0-OpenSSH_8.9`) and a synthetic KEXINIT packet, then wraps tunnel data in SSH binary packet framing with message type `0xFF`. The server authenticates the connection via HMAC-SHA256 over a shared token, accepting timestamps within a 300-second window.

Requires server: yes.

### IMAP Camouflage

Masquerades the tunnel as IMAP mailbox synchronization. Tunnel data is carried inside FETCH response bodies and APPEND literals, following the IMAP4rev1 wire format closely enough to pass shallow inspection. Authentication uses the same HMAC-SHA256 scheme as SSH Camouflage.

Requires server: yes.

### ICMP Tunnel

Encodes tunnel data inside ICMP Echo (ping) and Echo Reply (pong) packets. Most firewalls allow ICMP, making this a reliable last-resort. Requires `CAP_NET_RAW` or root.

Best as: emergency fallback when all TCP/UDP strategies are blocked.
