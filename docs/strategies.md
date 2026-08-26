# DPI Bypass Strategies

A strategy is a transport: it decides what the connection between client and
server looks like on the wire. The client registers a set of them at startup,
probes them, and picks one. If the active one dies mid-session, the client moves
to the next.

This page lists what the engine actually registers in v1.5.0, the exact IDs you
pass to `-strategy`, and where the code is honest about not being finished.

## Registered strategies

Sorted by priority. Lower priority = tried earlier.

| ID | Name | Transport | Priority | Registered when |
|----|------|-----------|---------:|-----------------|
| `quic_salamander` | QUIC Salamander | QUIC/UDP | 4 | `-quic` and not `-quic-sni-frag` |
| `reality` | REALITY Protocol | TLS/TCP | 5 | always |
| `quic` | QUIC Tunnel | QUIC/UDP | 5 | `-quic` |
| `http_polling` | HTTP Polling (meek-style) | HTTP/1.1 | 6 | always |
| `seqovl` | Seqovl | TLS/TCP | 7 | always |
| `http2_stego` | HTTP/2 Steganography | HTTP/2 | 7 | always |
| `websocket_padded` | WebSocket Salamander | WebSocket | 8 | always |
| `morph_Yandex Video` | Traffic Morph (Yandex) | TLS/TCP | 10 | always |
| `morph_VK Video` | Traffic Morph (VK) | TLS/TCP | 10 | always |
| `morph_Baidu Video` | Traffic Morph (Baidu) | TLS/TCP | 10 | always |
| `morph_Aparat Video` | Traffic Morph (Aparat) | TLS/TCP | 10 | always |
| `geneva_russia` | Geneva (Russia TSPU) | TCP | 12 | always |
| `geneva_china` | Geneva (China GFW) | TCP | 12 | always |
| `geneva_iran` | Geneva (Iran DPI) | TCP | 12 | always |
| `mesh_relay` | Mesh Relay | TCP | 15 | relay nodes configured — see note below |
| `antiprobe` | Anti-Probe Resistance | TLS/TCP | 20 | always |
| `confusion_0` | Protocol Confusion (DNS) | raw TCP | 25 | always |
| `confusion_1` | Protocol Confusion (HTTP) | raw TCP | 25 | always |
| `confusion_2` | Protocol Confusion (SSH) | raw TCP | 25 | always |
| `confusion_3` | Protocol Confusion (SMTP) | raw TCP | 25 | always |
| `confusion_4` | Protocol Confusion (Multi-Layer) | raw TCP | 25 | always |
| `ssh_camouflage` | SSH Camouflage | TCP | 28 | always |
| `imap_camouflage` | IMAP Camouflage | TCP | 29 | always |
| `state_exhaustion` | State Table Exhaustion | TCP | 50 | always |
| `icmp_tunnel` | ICMP Tunnel | ICMP | 70 | `-icmp-tunnel` |

"always" means: the client has a server address (`-server`, `-server-v6`, or a
`[[servers]]` list) and a secret. Without both, only `state_exhaustion` and the
five `confusion_*` entries register, and none of them will get you a tunnel.

`morph_*` needs the secret but not the server address, because it dials through
the manager's endpoint selector rather than a pinned address.

### `mesh_relay` is not reachable from the CLI

It registers only when `DefaultManagerConfig.RelayNodes` is non-empty, and no
flag or TOML key sets that field. Today it is a library-only strategy. It is
listed here so nobody spends an afternoon looking for the flag.

### Matching names on `-strategy`

`-strategy` matches by **case-sensitive ID prefix**, and keeps every strategy
that matches. Two consequences:

- `-strategy morph` keeps all four morph variants. `-strategy 'morph_Yandex'`
  keeps one (mind the space in the full ID — quote it).
- `-strategy confusion` keeps all five confusion variants. The individual IDs
  are `confusion_0` … `confusion_4`, not `confusion_dns` / `confusion_http`.
  The ID is derived from the enum ordinal, so the human-readable name in
  `-list` and the ID do not match.

An unmatched name is a startup error, not a silent fallback.

### `-list` shows a fixed set, not your configuration

```bash
tiredvpn client -list
```

`-list` builds a throwaway manager with a dummy server and secret and ignores
every other flag you passed. QUIC, ICMP and mesh never appear in its output
regardless of `-quic` / `-icmp-tunnel`. Use it to read IDs and descriptions,
not to confirm what your real run will register.

## Strategy details

### REALITY Protocol — `reality`

The default. Presents a TLS 1.3 handshake toward a donor SNI and hides
authentication in the ClientHello. Two transports live behind one ID:

- **Legacy** (default) — ClientHello bytes are emitted by hand, one ServerHello
  record is read back, then a hand-rolled stream cipher carries data. There is
  no ChangeCipherSpec, Finished or certificate; a stateful TLS parser sees the
  handshake stop halfway.
- **B1** (`-reality-server-pubkey <base64>`) — a genuine TLS 1.3 handshake end
  to end. Authentication rides in the 32 bytes of `session_id`; the server
  proves itself through the certificate signature field. Needs the server's
  static public key, so it is opt-in per deployment.

`-tls-fingerprint` picks the uTLS browser profile (default `firefox`), fixed for
the process lifetime on purpose. `-pq` plus `-pq-server-key` adds ML-KEM-768 /
ML-DSA-65 on top of the classical exchange. `-reality-require-data-v2` refuses
servers still on the v1 data layer instead of silently downgrading.

### Seqovl (TCP sequence overlap) — `seqovl`

Rides the REALITY handshake and attacks stateful DPI reassembly. Before the real
ClientHello the client writes one junk TLS handshake record carrying
`[nonce:16][marker:32][junk:32..224]`, where the marker is
`HMAC-SHA256(secret, "tiredvpn-seqovl-decoy-v1" || nonce)`. A reassembler
fingerprints the junk and misses the genuine first flight; the server recognises
the marker, drops the record, and parses the real ClientHello. Nonce, junk bytes
and junk length are randomised per connection.

The server's gate is cheap and additive: a genuine ClientHello body starts with
`0x01`, decoys force their first payload byte away from `0x01`, so REALITY,
Geneva and Morph handshakes never reach the HMAC comparison. The server drops at
most 4 leading decoys per connection.

Two levels:

- **App-framing (level B)** — always on when you select `seqovl`. Plain TLS
  record before the ClientHello, no privileges, works on Android.
- **Packet-level (level A, `-seqovl-packet`)** — real TCP segment overlap
  through the Geneva NFQUEUE injector. Linux only, needs `CAP_NET_ADMIN` plus an
  operator-provisioned `OUTPUT` NFQUEUE rule (queue 1). Purely additive: if the
  capability is missing it logs and stays on level B. The matching server-side
  drop is **not implemented** — `-seqovl-packet-drop` on the server logs a
  warning and turns itself off, and the client uses an overlap geometry the
  receiver's kernel discards on its own.

Seqovl does not run on the B1 transport. On B1 every ClientHello byte is
authenticated by `session_id`, so a prefix in front of it breaks the server's
AAD. That branch is deliberate, not missing work.

Roll servers before clients: a `seqovl` client against a server predating decoy
support fails REALITY auth on that strategy and falls back.

### QUIC — `quic`, `quic_salamander`

Both need `-quic`. `quic_salamander` pads QUIC Initial packets
([Salamander](https://arxiv.org/abs/2407.02996)) to remove the statistical
fingerprint DPI uses to spot QUIC. `-quic-sni-frag` fragments the SNI across
CRYPTO frames — it applies to the plain `quic` strategy, and when it is on
`quic_salamander` is **not registered at all** (the two are alternatives, not
layers).

`-quic-port` sets the plain-QUIC port (default 8443). The Salamander port comes
from `-quic-salamander-port` or, unset, from the port of `-server` / the first
endpoint. With a multi-endpoint pool on mixed ports the client warns: the
derived port is applied to whatever host the selector picks, so set it
explicitly.

### HTTP/2 Steganography — `http2_stego`

Carries tunnel data inside HTTP/2 DATA and HEADERS frames shaped like a gRPC
call to a Google API host, with NaiveProxy-style padding. `-cover` sets the
authority header (default `api.googleapis.com`). Accepts an ECH config
(`-ech`, `-ech-config`, `-ech-public-name`) to hide the outer SNI.

### WebSocket Salamander — `websocket_padded`

WebSocket upgrade followed by Salamander-padded frames. The server detects it by
the `Upgrade: websocket` header. No flags of its own.

### HTTP Polling — `http_polling`

Meek-style short-lived POST requests against a CDN-shaped path
(`/npm/jquery/dist/jquery.min.js`). The server keeps per-session state and
cleans up stale sessions. Latency and throughput are the worst of the TCP
strategies by construction — this is for networks where only plain HTTP
survives.

### Traffic Morphing — `morph_*`

Pads and buckets writes so the packet-size distribution matches a video
streaming service: Yandex, VK, Baidu, Aparat. Each profile is a packet-size
histogram plus a padding range. Inter-arrival parameters exist in the profile
but the morph strategy itself does not pace on them — timing comes from the
shaper when one is configured (see
[internal/shaper/README.md](../internal/shaper/README.md)). With `-shaper` set,
the negotiated shaper ID travels in the morph handshake so the server rebuilds
the same framing.

### Geneva — `geneva_russia`, `geneva_china`, `geneva_iran`

Applies country-specific packet manipulation (fragment, duplicate, reorder) from
the [Geneva](https://geneva.cs.umd.edu) engine. On Linux with `CAP_NET_ADMIN` it
injects through NFQUEUE; elsewhere it degrades to byte-level fragmentation of
the TLS ClientHello.

The engine also carries a `turkey` rule-set, but no ID registers it. Using it
needs a code change to add `NewGenevaStrategy(m, secret, "turkey")`.

### Anti-Probe — `antiprobe`

The server answers unauthenticated connections as an ordinary website and only
reveals the tunnel to a client that authenticates. Aimed at active probing.
Accepts the same ECH flags as `http2_stego`.

### Protocol Confusion — `confusion_0` … `confusion_4`

Raw TCP with a protocol preamble that reads as DNS-over-TCP, HTTP, SSH, SMTP or
several stacked headers, followed by a `TIRED` marker the server keys on. No TLS
wrapper — the preamble *is* the transport framing. Its probe is a bare TCP
connect, so a green probe says the port is open and nothing about whether the
confusion parses.

### SSH Camouflage — `ssh_camouflage`

Sends a real SSH banner and a synthetic KEXINIT, then wraps tunnel data in SSH
binary packet framing with message type `0xFF`. The server authenticates with
HMAC-SHA256 over a shared token and accepts timestamps inside a 300-second
window.

### IMAP Camouflage — `imap_camouflage`

Plays a mailbox sync: Dovecot-style greeting, LOGIN, SELECT, then payload inside
FETCH response bodies and APPEND literals. Same HMAC-SHA256 authentication as
SSH camouflage.

### State Table Exhaustion — `state_exhaustion`

Floods the DPI state table with decoy connections for two seconds hoping to push
it into fail-open, then dials the real connection. The flood needs raw sockets;
without `CAP_NET_RAW` (and always on Android) it skips the flood entirely and
degenerates into a plain connect. It is the only registered strategy that
reports `RequiresServer: false`, and its priority (50) keeps it out of the way.

### ICMP Tunnel — `icmp_tunnel` — known broken

Off by default. Needs `-icmp-tunnel` on the client (`CAP_NET_RAW`) and
`-enable-icmp` on the server. Data rides in ICMP Echo / Echo Reply payloads at
10 pps in stealth mode.

**The handshake does not complete against a stock Linux server.** The client
issues a single `ReadFrom` and accepts the first ICMP packet arriving from the
server address. A Linux kernel answers the Echo Request itself, before userspace
sees it, with the identical payload echoed back. That reply passes the magic,
version and session-ID checks and then fails AEAD open — the client returns
`handshake: server auth failed` and gives up rather than reading the next
packet. The transport framing below the handshake is fine; the handshake read
loop is the defect. Treat this strategy as unavailable.

## How the adaptive engine works

### Ordering

Strategies are kept sorted by

```
score = priority - confidence * 10      # lower is better
```

Confidence starts at 0.5 and moves as an exponential moving average (α = 0.3) of
probe and connect outcomes, plus 0.1 if the strategy succeeded in the last five
minutes, minus 0.15 per consecutive failure (capped at three), plus 0.1 recovery
if it has been failing but unused for ten minutes. It is clamped to 0.05–0.95 so
nothing is ever permanently excluded.

Latency is measured and averaged per strategy and shown in `-list`, but it does
**not** enter the ordering. Neither does raw success rate — only the confidence
EMA does.

In Android mode, UDP strategies take an additional penalty that starts at +10
and drops by 5 per consecutive TCP timeout, reaching 0 after two. TCP is tried
first; QUIC gets its turn once TCP has demonstrably failed.

### Probing

`ProbeAll` fans out over every strategy with priority > 0 and probes the
endpoint the selector has pinned — not the whole `[[servers]]` pool. Probes are
deliberately shallow (most are a plain TCP connect), so a successful probe means
reachable, not working.

### Circuit breakers

Each strategy has its own breaker with a sliding window of the last 20 outcomes
over 2 minutes:

- **Closed** — available.
- **Open** — tripped after 5 consecutive failures, or a failure rate above 70%
  (85% when RTT variance suggests an unstable link) over at least 5 samples.
- **Half-open** — after the reset timeout, 3 test requests are allowed and 2 must
  succeed. The reset timeout backs off 30s → 1m → 2m → 5m.

`-circuit-threshold` and `-circuit-reset` are parsed and logged but **not wired
into the manager**; the breaker uses the fixed defaults above. Same for
`-fallback`: mid-session fallback is unconditional and the flag changes nothing.

### Mid-session fallback

When the active strategy fails, the client moves to the next in sorted order and
re-establishes. Losing every strategy at once triggers an emergency re-probe,
rate-limited to once a minute.

### Periodic re-probing

Every `-reprobe-interval` (default 5m) all strategies with priority > 0 are
re-probed, including ones whose breaker is open, under a 2-minute cap. This flag
*is* wired.

## Choosing a strategy

### Automatic

Leave `-strategy` unset.

```bash
tiredvpn client -server host:443 -secret <s> -listen 127.0.0.1:1080
```

### Forced

```bash
tiredvpn client -server host:443 -secret <s> -strategy reality
```

### By censorship environment

The code carries country-specific *artifacts* — Geneva rule-sets, morph profiles
and RTT profiles named after Russian, Chinese and Iranian services. Those names
describe what a strategy imitates. They are not a measured ranking, and this
repository holds no published efficacy numbers per country. Pick candidates from
the list below, then settle it with `-benchmark` on your own path.

| Environment | Artifacts built for it |
|---|---|
| Russia (TSPU) | `geneva_russia`, `morph_Yandex Video`, `morph_VK Video`, `seqovl`, RTT profiles `moscow-yandex`, `moscow-vk`, `regional-russia`, `siberia` |
| China (GFW) | `geneva_china`, `morph_Baidu Video`, `-quic-sni-frag`, RTT profile `beijing-baidu` |
| Iran | `geneva_iran`, `morph_Aparat Video`, `http2_stego`, RTT profile `tehran-aparat` |
| SNI-based blocking | `reality` (no plaintext SNI on B1), `-ech` on `http2_stego` / `antiprobe` |

```bash
tiredvpn client \
  -server host:443 \
  -secret <s> \
  -quic -quic-sni-frag \
  -rtt-masking -rtt-profile moscow-yandex
```

`-rtt-profile` accepts `moscow-yandex`, `moscow-vk`, `regional-russia`,
`siberia`, `cdn`, `beijing-baidu`, `tehran-aparat` (default `moscow-yandex`) and
only takes effect with `-rtt-masking`.

## Benchmarking

```bash
# Latency across registered strategies
tiredvpn client -server host:443 -secret <s> -benchmark

# Same, machine-readable on stdout (logs go to stderr)
tiredvpn client -server host:443 -secret <s> -benchmark-json

# Latency + throughput + exit-IP check
tiredvpn client -server host:443 -secret <s> -benchmark-full

# All strategies × all RTT profiles (78 combinations)
tiredvpn client -server host:443 -secret <s> -benchmark-all
```

The benchmark covers the strategies your flags actually registered, so pass
`-quic` / `-icmp-tunnel` if you want those measured. Results are specific to
your path and your censor; there are no useful reference numbers to publish
here.
