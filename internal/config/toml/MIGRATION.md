# tiredvpn — CLI to TOML migration

tiredvpn is moving its primary configuration surface from CLI flags to TOML
(`client.toml` / `server.toml`). The `internal/config/toml` package now provides
a layered resolver so the transition stays backwards-compatible:

```
defaults  <  TOML file  <  CLI flags
```

A flag wins only when it was explicitly passed on the command line. A flag left
at its default value never silently overwrites a TOML field.

## Flag → TOML mapping

### Client (`tiredvpn client ...`)

| Old CLI flag                  | New TOML location              | Notes                              |
|-------------------------------|--------------------------------|------------------------------------|
| `--server=host:port`          | `[server] address` + `port`    | host:port string is split          |
| `--strategy=NAME`             | `[strategy] mode`              |                                    |
| `--debug`                     | `[logging] level = "debug"`    | flag forces level only when `true` |

Flags not yet represented in the TOML schema (`--listen`, `--secret`,
`--tun-*`, benchmark/probe knobs, `--list`, etc.) continue to be read directly
from the FlagSet by `cmd/tiredvpn`. They will be migrated in follow-up issues.

### Server (`tiredvpn server ...`)

| Old CLI flag                  | New TOML location              | Notes                                |
|-------------------------------|--------------------------------|--------------------------------------|
| `--listen=host:port`          | `[listen] address` + `port`    | host:port string is split            |
| `--cert=PATH`                 | `[tls] cert_file`              |                                      |
| `--key=PATH`                  | `[tls] key_file`               |                                      |
| `--debug`                     | `[logging] level = "debug"`    | flag forces level only when `true`   |

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

## Compatibility timeline

- **v1.x (current)**: every legacy flag still works exactly as before. The TOML
  loader is opt-in via `--config=PATH`.
- **v2.0**: the TOML resolver becomes the canonical entry point. Flags listed
  in the table above continue to function as overrides; non-mapped flags will
  emit a deprecation warning.
- **v3.0**: only flags in the override mapping remain. All other configuration
  must come from TOML.

Concrete version numbers are tracked in issue #6.
