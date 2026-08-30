# tiredvpn — CLI to TOML migration

tiredvpn is moving its primary configuration surface from CLI flags to TOML
(`client.toml` / `server.toml`). The `internal/config/toml` package provides a
layered resolver so the transition stays backwards-compatible:

```
defaults  <  TOML file  <  CLI flags
```

A flag wins only when it was explicitly passed on the command line
(`flag.Visit`, not `VisitAll`). A flag left at its default value never silently
overwrites a TOML field.

Unknown keys are rejected by the decoder. A typo does not fall through to a
default: loading fails and the error names the key and its position.

## Flag → TOML mapping

### Client (`tiredvpn client ...`)

| Old CLI flag                  | New TOML location              | Notes                              |
|-------------------------------|--------------------------------|------------------------------------|
| `--server=host:port`          | `[server] address` + `port`    | host:port split; collapses `[[servers]]` to its first entry |
| `--server-v6=[host]:port`     | `[server] address_v6` + `port_v6` | same collapse; `port_v6` defaults to `port` |
| `--server-policy=NAME`        | `[selection] policy`           | `priority` (default), `latency`, `weighted` |
| `--prefer-ipv6` / `--fallback-v4` | `[selection] family`       | `true`+`true` → `prefer_v6`, `true`+`false` → `v6_only`, `false` → `v4_only` for any fallback |
| `--strategy=NAME`             | `[strategy] mode`              | optional; empty means the client picks |
| `--tls-fingerprint=NAME`      | `[tls] fingerprint`            | **exception to the precedence rule**: a non-empty key in the file overwrites the flag |
| `--tun-ipv6-allow=LIST`       | `[tun] ipv6_allow`             | comma-separated flag, one entry per array element in the file; the flag replaces the list, it does not extend it |
| `--shaper=NAME`               | `[shaper] preset`              | an explicit `--shaper` is applied after TOML and wins |
| `--shaper-seed=N`             | `[shaper] seed`                | the flag is read only alongside `--shaper`; the file's `seed` belongs to `[shaper]` |
| `--debug`                     | `[logging] level = "debug"`    | flag forces level only when `true`; no other level value does anything yet |

A list of servers has no flag equivalent: `[[servers]]` is config-file only,
and `[server]` is defined to be a one-element list (setting both is an error).
See [docs/client.md](../../../docs/client.md#several-servers) for the per-entry
fields and the `[selection]` knobs.

`--server` and `--server-v6` keep the first entry of a `[[servers]]` list
rather than discarding it, so a `name` or `secret` attached to that entry
survives the collapse; only the addresses are replaced. Collapsing a list of
more than one logs a warning.

### Server (`tiredvpn server ...`)

| Old CLI flag                  | New TOML location              | Notes                                |
|-------------------------------|--------------------------------|--------------------------------------|
| `--listen=host:port`          | `[listen] address` + `port`    | host:port string is split            |
| `--cert=PATH`                 | `[tls] cert_file`              |                                      |
| `--key=PATH`                  | `[tls] key_file`               |                                      |
| `--debug`                     | `[logging] level = "debug"`    | flag forces level only when `true`   |

## Keys accepted but not yet applied

These parse and validate, and then nothing consumes them. They are listed so a
config that sets one is not mistaken for a config that changes behaviour.

Client: `[strategy] options`, `[tls] server_name`, `[tls] alpn`,
`[tls] ca_cert`, `[tls] insecure_skip_verify`, `[logging] format`,
`[logging] output`, and the per-entry `sni` override on a server.
`[selection] policy` other than `priority`, `health_check = "active"` and
`recheck_interval` are validated and warned about on startup; candidates stay
in configuration order.

Server: `[strategy] mode`, `[auth] mode`, `[auth] tokens`,
`[auth] tokens_file`, `[tls] alpn`, `[tls] client_ca_file`. `[shaper]` is
parsed into `server.Config.Shaper` but the server pipeline does not consume it
yet. Note that `strategy.mode`, `auth.mode`, `tls.cert_file` and `tls.key_file`
are *required* by the server schema even though nothing reads the first two
yet: a server config that omits them fails validation.

## Flags with no TOML key

Everything not in the tables above is still read straight from the FlagSet by
`cmd/tiredvpn`: `--listen` and `--secret` on the client, the `--tun-*` family
except `--tun-ipv6-allow` (`--tun-ipv6` itself included, so its default of
`dual` applies to a TOML-only client as well), port hopping, ECH,
post-quantum, REALITY B1,
burst-reshape, benchmarking, `--api-addr`, `--pprof`, `--list`. They will be
migrated in follow-up issues.

## Example

Before:

```
tiredvpn client \
  --server=vpn.example.com:443 \
  --strategy=reality \
  --debug
```

After (`client.toml`):

```toml
[server]
address = "vpn.example.com"
port = 443

[strategy]
mode = "reality"

[logging]
level = "debug"
```

Run with:

```
tiredvpn client --config=client.toml
```

## How precedence works

Given this `client.toml`:

```toml
[server]
address = "vpn.example.com"
port = 443

[strategy]
mode = "reality"
```

and the invocation:

```
tiredvpn client --config=client.toml --server=staging.example.com:8443
```

`ResolveClient` produces:

| Field             | Value                  | Source        |
|-------------------|------------------------|---------------|
| `server.address`  | `staging.example.com`  | CLI flag      |
| `server.port`     | `8443`                 | CLI flag      |
| `strategy.mode`   | `reality`              | TOML          |
| `logging.level`   | `info`                 | default       |
| `logging.format`  | `text`                 | default       |
| `tls.alpn`        | `["h2","http/1.1"]`    | default       |

If `--strategy` is omitted, the TOML value sticks. If it is passed (even with a
value identical to the default), it overrides TOML — explicit user intent wins.

One key does not follow the rule. `--tls-fingerprint` is not part of the flag
overlay, and the value from the file is applied afterwards, so with both set
the file wins. Every other mapped key behaves as the table says.

### Two things the merge does not do

**Lists are atomic.** `[[servers]]` from the file replaces the default list
outright; it is never merged entry-by-entry, because "entry 2 of the file" and
"entry 2 of the defaults" are not the same server and no reader could predict
the result. `tls.alpn` behaves the same way: it replaces, it does not append.

**`[selection]` is copied whole.** Presence of the block is what matters —
`ClientConfig.Selection` is a pointer so "absent" stays distinguishable from
"present and all-zero". Absent means the legacy `--prefer-ipv6` /
`--fallback-v4` flags decide the address family; present with an empty `family`
means the same thing, said explicitly.

## Migrating a server list

Before, one endpoint per client process:

```
tiredvpn client --server=203.0.113.10:443 --server-v6=[2001:db8::10]:443
```

After, a pool with failover:

```toml
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
max_cooldown      = "30m"
min_dwell         = "5m"
```

Two constraints that bite during this migration:

- **One secret for the whole list.** The per-entry `secret` key exists, but a
  strategy bakes the secret in when it is constructed, so it cannot change on a
  switch. Entries that disagree with each other, or with `--secret`, are a
  startup error. One `secret` repeated on every entry is fine and becomes the
  client's secret.
- **`--server` still collapses the list.** A systemd unit that passes
  `--server` alongside `--config` gets one endpoint and a warning, not a pool.
  Drop the flag when you add `[[servers]]`.

## Compatibility timeline

- **v1.x (current)**: every legacy flag still works exactly as before. The TOML
  loader is opt-in via `--config=PATH`.
- **v2.0**: the TOML resolver becomes the canonical entry point. Flags listed
  in the table above continue to function as overrides; non-mapped flags will
  emit a deprecation warning.
- **v3.0**: only flags in the override mapping remain. All other configuration
  must come from TOML.

Concrete version numbers are tracked in issue #6.
