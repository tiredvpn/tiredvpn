# Client Reference

Complete reference for `tiredvpn client`.

## Usage

```
tiredvpn client [options]
tiredvpn client --config /etc/tiredvpn/client.toml
```

Options come from three layers, in this order of precedence:

```
CLI flag  >  TOML file (--config)  >  built-in default
```

A flag counts as "given" only when it appears on the command line. A flag left
at its default never overwrites a TOML value.

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

Since 1.5.0 TUN mode also takes IPv6 out of the host's hands by default - see
[IPv6 inside the tunnel](#ipv6-inside-the-tunnel).

## Flag Reference

### CORE OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | | Remote server address (`host:port`). Required unless the config file names one |
| `-secret` | | Shared secret for authentication. Falls back to `TIREDVPN_SECRET` |
| `-config` | | Path to a TOML config file (see [Configuration via TOML](#configuration-via-toml)) |
| `-listen` | `127.0.0.1:1080` | Local proxy address (SOCKS5/HTTP auto-detect) |
| `-http-listen` | | Separate HTTP proxy address (optional) |
| `-cover` | `api.googleapis.com` | Cover host for traffic mimicry (SNI / Host header). Process-wide |
| `-strategy` | | Force a specific strategy; skips auto-selection |
| `-list` | `false` | Print available strategies and exit |
| `-debug` | `false` | Enable verbose debug logging |
| `-version` | | Print version and exit |

An address is required from somewhere: `-server`, `-server-v6`,
`server.address` or a `[[servers]]` entry. With none of them the client exits
with `-server is required`.

`-secret` is not enforced the same way. With no flag and no `TIREDVPN_SECRET`
the client logs `No secret provided - using default (INSECURE!)` and continues
with a built-in placeholder, which no real server will accept. Prefer the env
var over the flag on a shared host: an argument is readable through `/proc`.

To see all available strategy IDs:

```bash
tiredvpn client -list
```

### TRANSPORT FAMILY AND SERVER SELECTION

| Flag | Default | Description |
|------|---------|-------------|
| `-server-v6` | | Server IPv6 address (e.g., `[2001:db8::1]:995`) |
| `-prefer-ipv6` | `true` | Try IPv6 transport first when the server has one |
| `-fallback-v4` | `true` | Fall back to IPv4 if IPv6 fails |
| `-server-policy` | | Order of the `[[servers]]` list: `priority`, `latency`, `weighted`. Empty = `priority` |

These flags describe the *transport* - how the client reaches the server. They
are unrelated to `-tun-ipv6`, which describes what the tunnel carries.

The two legacy flags map onto the `selection.family` policy:

| `-prefer-ipv6` | `-fallback-v4` | Family policy |
|---|---|---|
| `true` | `true` | `prefer_v6` (default) |
| `true` | `false` | `v6_only` |
| `false` | any | `v4_only` |

`-prefer-ipv6=false` has always meant "IPv4, and do not probe IPv6 at all", so
there is no flag combination that produces `prefer_v4` - it is reachable only
from the config file.

#### Runtime fallback

The family is no longer decided once per process. Each (server, family) pair is
a dial candidate with its own health:

- Two failed connect cycles park a candidate (`selection.failure_threshold`).
- A parked candidate stays parked for `cooldown`, doubling per repeat up to
  `max_cooldown`, jittered by ±20% so clients that lost the same server do not
  all return at the same instant.
- The client holds a fallback for at least `min_dwell` before it is allowed
  back to a more preferred candidate.
- Re-evaluation happens only at a reconnect boundary, so it rides a dial that
  was going to happen anyway and adds no traffic of its own.
- When every candidate is parked the least-bad one is un-parked rather than
  leaving the client with nowhere to go.

Defaults are `failure_threshold=2`, `cooldown=1m`, `max_cooldown=30m`,
`min_dwell=5m`; tune them in `[selection]`.

### TUN MODE (Full VPN)

| Flag | Default | Description |
|------|---------|-------------|
| `-tun` | `false` | Enable TUN mode |
| `-tun-name` | `tiredvpn0` | TUN device name |
| `-tun-ip` | `10.8.0.2` | Local TUN IP address |
| `-tun-peer-ip` | `10.8.0.1` | Remote TUN peer IP (server side) |
| `-tun-mtu` | `1280` | TUN device MTU, 1280-9000. With `-auto-mtu` this is the upper bound |
| `-auto-mtu` | `true` | Probe the real end-to-end MTU and apply `min(probed, -tun-mtu)`; floor 1280 |
| `-tun-routes` | | Comma-separated CIDRs to route through VPN |
| `-tun-ipv6` | `dual` | What happens to IPv6 while the tunnel is up: `dual`, `block`, `off` |
| `-tun-fd` | `-1` | Use an existing TUN file descriptor (Android VpnService) |

An MTU outside 1280-9000 is a startup error, whether it came from the flag or
from a config file.

`-tun-routes 0.0.0.0/0` routes all IPv4. For split tunnel, list specific CIDRs:

```bash
-tun-routes 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

#### Server bypass routes

When the installed route set swallows the server's own address - a default
route, or the `0.0.0.0/1` + `128.0.0.0/1` pair - the client pins a `/32` (or
`/128`) host route to it through the physical gateway, so the transport
connection does not loop back into the tunnel it carries.

Every configured address is pinned at startup, not the one currently in use.
With a server list that matters: dialling the second server without a pin of
its own would route that dial into the tunnel and it would die there. A host
route that already existed before the client started is left in place on
teardown - it belongs to the operator, and on a host with no default route for
that family it is the only path to the server.

#### IPv6 inside the tunnel

`-tun-ipv6` decides what happens to the host's IPv6 while the tunnel is up. It
defaults to `dual` as of 1.5.0; before that it was `off`.

| Value | Handshake | Effect |
|-------|-----------|--------|
| `dual` | `0x04` | Negotiate IPv6 tunnel addresses with the exit and route IPv6 through the tunnel (`::/1` + `8000::/1`). If the exit declines, fall back to blocking |
| `block` | `0x03` | Never ask the exit for IPv6; reject outbound IPv6 for the life of the tunnel |
| `off` | `0x03` | IPv4-only tunnel, host IPv6 untouched - on a dual-stack host it bypasses the VPN |

The reason for the new default is issue #55: on a dual-stack host a v4-only
tunnel is simply stepped around. Every application with a working IPv6 default
route reached the internet outside the VPN and handed out the user's real
address.

Blocking is a per-interface nftables table in the `ip6` family, hooked at
output, installed after the connect and removed with the tunnel. It rejects
with ICMPv6 admin-prohibited rather than dropping, so applications fail over to
IPv4 immediately instead of waiting out a timeout. Loopback, the tunnel itself,
link-local (`fe80::/10`), multicast (`ff00::/8`) and the server's own IPv6
addresses stay reachable.

Platform coverage: Linux only. On macOS the blocking half is not implemented
and the client warns once per session. On Android filtering belongs to
`VpnService`, and the block is skipped because the client does not own the
interface.

Two things to know before flipping this on:

- **Split tunnels change behaviour.** `dual` sends *all* IPv6 into the tunnel,
  including destinations deliberately routed around it on IPv4. If you route a
  prefix list rather than a full tunnel and want the old split, set
  `-tun-ipv6 off`.
- **Upgrade exits and relays first.** Against an exit that predates dual-stack
  a `0x04` client pays a 300 ms flags-byte grace on every connect and logs a
  warning. Against an exit without `-ip-pool-v6` the negotiation simply does
  not succeed and the session stays IPv4-only.

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
| `-port-hop-interval` | `1m` | How often to hop (each cycle jittered ±30%) |
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
| `-quic-port` | `8443` | Server QUIC port |
| `-quic-sni-frag` | `false` | Fragment QUIC Initial SNI (GFW bypass) |
| `-tls-fingerprint` | | uTLS browser profile for the ClientHello; empty uses `firefox` |
| `-seqovl-packet` | `false` | Packet-level TCP sequence overlap for the `seqovl` strategy; additive to the app-framing decoy. Linux + `CAP_NET_ADMIN` + an `OUTPUT` NFQUEUE rule. Off = app-framing only (works everywhere, incl. Android) |
| `-icmp-tunnel` | `false` | Enable the ICMP tunnel as a backup strategy. Needs `CAP_NET_RAW`; server must run with `-enable-icmp` |
| `-ech` | `false` | Enable Encrypted Client Hello (hides SNI) |
| `-ech-config` | | ECHConfigList in base64 (from server) |
| `-ech-public-name` | `cloudflare-ech.com` | Outer SNI visible to network when using ECH |
| `-pq` | `false` | Enable post-quantum crypto (ML-KEM-768 + ML-DSA-65) |
| `-pq-server-key` | | Server's ML-KEM public key in base64 |
| `-rtt-masking` | `false` | Enable RTT masking (hides proxy timing signature) |
| `-rtt-profile` | `moscow-yandex` | RTT profile to emulate (see table below) |
| `-reality-server-pubkey` | | Server's static REALITY public key, base64. Non-empty selects the B1 transport |
| `-reality-require-data-v2` | `false` | Refuse REALITY servers still on the v1 data layer instead of falling back |
| `-burst-reshape` | `off` | Split the inner TLS handshake with a nudge/ack exchange: `off`, `on`. Must match the server |
| `-burst-reshape-pad-flight` | `0` | Extra bytes the server adds to its flight (0 = off). Must match the server |

#### TLS fingerprint

`-tls-fingerprint` picks the uTLS profile the ClientHello is built from. Valid
names:

```
chrome  chrome120  chrome133  firefox  firefox120  firefox148
safari  edge  ios  android  randomized
```

An unrecognised name is not an error: the client warns and falls back to
`firefox`. The profile is fixed for the process lifetime on purpose - rotating
fingerprints after a censor throttles a SNI escalates the penalty.

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

An unknown profile name warns and falls back to `moscow-yandex`.

RTT masking adds artificial delay jitter that matches the chosen profile, making the VPN connection statistically indistinguishable from regular browsing to the chosen service.

#### REALITY B1 transport

`-reality-server-pubkey` switches the REALITY client onto the B1 transport (a
real TLS 1.3 handshake with authentication in `session_id`). There is no
probing and no downgrade on error: a transport that falls back when the
handshake fails is a transport a censor can force back to the old one. Generate
the pair on the server with `tiredvpn reality-keygen` and hand the client the
public half.

`-reality-require-data-v2` closes the v1 downgrade path for the data layer.
Turn it on only after every server is on 1.4.2 or later; the server has the
matching `-reality-require-data-v2`.

#### Burst reshape

`-burst-reshape on` splits the inner TLS handshake with a nudge/ack exchange so
the nDPI burst heuristic stops matching. Both settings are part of the wire
format: a one-sided `on`, or a `-burst-reshape-pad-flight` that differs between
the ends, corrupts streams.

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

`-fallback` is strategy fallback and nothing else. Moving between servers is
`-server-policy` and `[selection]`; the two names are separate because one flag
cannot mean both.

### BENCHMARKING

| Flag | Default | Description |
|------|---------|-------------|
| `-benchmark` | `false` | Test all strategies: latency only |
| `-benchmark-full` | `false` | Full benchmark: HTTP, latency, throughput, IP change |
| `-benchmark-all` | `false` | Exhaustive: all strategies x all RTT profiles (78 combinations) |
| `-benchmark-json` | `false` | Run benchmark for one strategy, output JSON result to stdout (logs go to stderr) |
| `-shaper-seed` | `0` | Deterministic seed for shaper randomization (0 = random) |

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

See [monitoring.md](monitoring.md) for Prometheus metrics details.

## Configuration via TOML

Since v1.1.0 the client accepts `--config <path>` to load options from a TOML
file. Any CLI flag passed alongside overrides the file value (precedence:
CLI > TOML > defaults), so existing scripts keep working.

```bash
tiredvpn client --config /etc/tiredvpn/client.toml
```

A copy-paste-ready template lives in [`configs/client.example.toml`](../configs/client.example.toml).

Unknown keys are rejected. A typo does not fall through to a default; the
client refuses to start and names the offending key and line.

Minimal example:

```toml
[server]
address = "vpn.example.com"
port    = 443

[strategy]
mode = "morph"

[shaper]
preset = "chrome_browsing"

[logging]
level = "info"
```

`strategy.mode` is optional: leave it out to let the client pick a strategy,
which is what the bare `-strategy` default does.

### Schema

| Section | Key | Type | Effect |
|---------|-----|------|--------|
| `[server]` / `[[servers]]` | see below | | the endpoint list |
| `[selection]` | see below | | which endpoint is dialled, and when it is given up on |
| `[strategy]` | `mode` | string | same as `-strategy`; empty means auto-select |
| `[strategy]` | `options` | table | accepted, not yet read by the runtime |
| `[shaper]` | `preset` | string | same as `-shaper` |
| `[shaper]` | `custom` | table | inline distributions; mutually exclusive with `preset` |
| `[shaper]` | `seed` | int | fixed seed; omit for per-session entropy |
| `[shaper]` | `randomization_range` | float | jitter applied to distribution samples, `[0, 1)` |
| `[tls]` | `fingerprint` | string | same as `-tls-fingerprint`, with one exception to the precedence rule: a non-empty value here overwrites the flag |
| `[tls]` | `server_name` | string | accepted, not yet read by the runtime (use `-cover`) |
| `[tls]` | `alpn` | array | accepted, not yet read by the runtime |
| `[tls]` | `ca_cert` | string | accepted, not yet read by the runtime |
| `[tls]` | `insecure_skip_verify` | bool | accepted, not yet read by the runtime |
| `[logging]` | `level` | string | only `"debug"` acts on anything - it turns on debug logging, as `-debug` does |
| `[logging]` | `format` | string | accepted, not yet read by the runtime |
| `[logging]` | `output` | string | accepted, not yet read by the runtime |

"Accepted, not yet read" means the loader validates the key and then nothing
consumes it. It is listed rather than hidden so a config that sets it is not
mistaken for a config that changes behaviour.

The TUN, port-hopping, ECH, post-quantum, benchmarking and monitoring knobs
have no TOML keys at all and stay command-line only - including `-tun-ipv6`,
whose default therefore applies to a TOML-only client too. See the
[migration guide](../internal/config/toml/MIGRATION.md) for the field-by-field
table.

### Several servers

`[server]` describes one endpoint. `[[servers]]` describes a list of them, and
a lone `[server]` is defined to be a one-element list - so setting both is a
startup error rather than a silent choice between the two.

```toml
[[servers]]
name       = "ams"
address    = "203.0.113.10"
port       = 443
address_v6 = "2001:db8::10"   # same server over IPv6; port_v6 defaults to port
weight     = 100

[[servers]]
name    = "fra"
address = "203.0.113.20"
port    = 443
weight  = 50

[selection]
policy            = "priority"   # priority (list order) | latency | weighted
family            = "prefer_v6"  # prefer_v6 | prefer_v4 | v6_only | v4_only
failure_threshold = 2            # failed connect cycles before a server is parked
cooldown          = "1m"         # first cooldown; doubles per repeat, jittered
max_cooldown      = "30m"
min_dwell         = "5m"         # hold a fallback this long before going back
health_check      = "off"        # off | active
recheck_interval  = "5m"         # only used when health_check = "active"
```

Per-entry fields: `name` (unique, used in logs), `address`, `port`,
`address_v6`, `port_v6`, `weight`, and the overrides `secret` and `sni`. An
entry needs at least one of `address` / `address_v6`; an omitted port is 443,
and `port_v6` follows `port`. Ports outside 1..65535 and duplicate names are
startup errors.

Durations in `[selection]` are strings (`"1m"`, `"30s"`), not bare numbers: a
number in a config file is a unit waiting to be guessed wrong. A
`max_cooldown` shorter than `cooldown` is rejected.

Notes worth reading once:

- **`secret` is per server.** Each entry may carry its own; the key travels
  with the dial, so switching server switches the key with it, along with
  everything derived from it (the REALITY donor pool, the client identifier the
  server looks you up by). Entries that disagree are normal, not an error.
  `-secret` / `TIREDVPN_SECRET` is the default for entries that name none of
  their own - the two no longer compete. A list where some entries carry a
  secret, some do not, and no default is configured anywhere IS a startup
  error: that config has no key for half its servers, and the likeliest cause
  is a missed line. If every entry agrees on one `secret` and nothing else
  named a default, that value becomes the client's, which is what lets the
  config file be the only place a secret appears.
- **`sni` is recorded but not applied yet**: the cover host is still
  process-wide (`-cover`). The client says so in the log rather than pretending.
- **`policy` other than `priority`, and `health_check = "active"`, are not
  applied yet.** The value is validated (a misspelling is a startup error) and
  then warned about on startup; candidates stay in configuration order, and the
  client still learns about a server only by dialling it. `recheck_interval`
  set without `health_check = "active"` warns too. `health_check` stays off by
  default on purpose: walking N servers on a timer is a periodic fan-out
  pattern with no cover traffic behind it.
- **`-server` / `-server-v6` collapse the list** to a single endpoint, with a
  warning. The first entry is kept and only its addresses are replaced, so its
  name and secret survive. One consequence: an entry that never spelled out
  `port_v6` still follows `port`, so `-server host:443` moves the IPv6 port to
  443 as well. Pin `port_v6` in the file, or pass `-server-v6`, to keep the two
  apart.
- **`-server-policy` sets `selection.policy`** from the command line;
  `-fallback` was already taken by strategy fallback, hence the longer name.
- **Address family.** Omitting `selection.family` keeps
  `-prefer-ipv6`/`-fallback-v4` in charge, per the mapping table
  [above](#transport-family-and-server-selection). `prefer_v4` is reachable
  only from the config file.

## Traffic Shaper

The shaper is a behavioural masking layer that sits between strategy and
transport. Strategies (REALITY, morph, etc.) hide *what* you send; the shaper
hides *the timing and sizes of how you send it*, so DPI cannot cluster
multiple users by their packet-distribution histogram.

Enable on the command line with `-shaper <preset>`, or via the `[shaper]`
section in TOML. An explicit `-shaper` flag overrides any `[shaper]` value in
the config file.

| Flag | Default | Description |
|------|---------|-------------|
| `-shaper` | | Traffic shaper preset (see table below): `youtube_streaming`, `chrome_browsing`, `imap_sync`, `random_per_session` |
| `-shaper-seed` | `0` | Seed for deterministic shaper (0 = random) |

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -strategy morph \
  -shaper chrome_browsing
```

Available presets:

| Preset                 | Use case                            | Throughput    | Trade-off                                |
|------------------------|-------------------------------------|---------------|------------------------------------------|
| `chrome_browsing`      | HTTPS browsing mimicry              | ~191 MB/s     | ~80% overhead vs. unshaped, recommended  |
| `youtube_streaming`    | HD video streaming mimicry          | sleep-bound   | bulk transfer caps in single-digit MB/s  |
| `random_per_session`   | rotates basis preset per connection | sleep-bound   | hardest to fingerprint, same caveat      |
| `bittorrent_idle`      | cover traffic only                  | n/a           | rejected in data plane (median ~7 s)     |
| `imap_sync`            | IMAP desktop client cadence         | n/a           | DataPlaneSafe=false - cover traffic only, not for real data plane (LogNormal inter-arrival ~36s median) |

The two cover-traffic presets are rejected rather than ignored: naming
`bittorrent_idle` or `imap_sync` on `-shaper` or in `[shaper] preset` is a
startup error, so a misconfiguration cannot silently collapse throughput.

Recommendation: start with `chrome_browsing`. Switch to
`random_per_session` when you specifically need the rotation property
(adversary collects long traces). Use `youtube_streaming` only on
interactive / non-bulk workloads.

Custom distributions are supported via `[shaper.custom]` - see the example
config and the [shaper README](../internal/shaper/README.md) for histogram /
log-normal / Pareto / Markov-burst parameter shapes.

If you do not need DPI shape masking, omit `[shaper]` entirely; throughput
defaults to native (>1 GB/s on loopback).

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

IPv6 is set to `off` here on purpose: `dual` would send all IPv6 into the
tunnel, which is not a split tunnel any more.

```bash
sudo tiredvpn client \
  -server your-server.com:443 \
  -secret <secret> \
  -tun \
  -tun-name tiredvpn0 \
  -tun-ip 10.8.0.2 \
  -tun-peer-ip 10.8.0.1 \
  -tun-routes 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  -tun-ipv6 off
```

### Server pool with failover

```toml
# /etc/tiredvpn/client.toml
[[servers]]
name       = "ams"
address    = "203.0.113.10"
port       = 443
address_v6 = "2001:db8::10"

[[servers]]
name    = "fra"
address = "203.0.113.20"
port    = 443

[selection]
failure_threshold = 2
cooldown          = "1m"
min_dwell         = "5m"

[strategy]
mode = "reality"
```

```bash
sudo tiredvpn client --config /etc/tiredvpn/client.toml \
  -secret <secret> \
  -tun \
  -tun-routes 0.0.0.0/0
```

Both servers get a bypass host route at startup, so the failover dial does not
route into the tunnel.

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
