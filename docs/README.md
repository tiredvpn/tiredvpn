# TiredVPN Documentation

Start with [Getting Started](getting-started.md) if you have never run
TiredVPN. Everything else is reference material and can be read out of order.

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | First-time setup: install, server, client, SOCKS5 and TUN mode |
| [Server Reference](server.md) | All server flags, forwarding and NAT, configuration examples |
| [Client Reference](client.md) | All client flags, the server pool, evasion options, RTT profiles |
| [Admin & Client Management](admin.md) | Multi-client mode, REST API, QR codes |
| [DPI Bypass Strategies](strategies.md) | Strategy list, adaptive engine, by-country guidance |
| [Architecture](architecture.md) | Internals: connection flow, auth, multiplexing, TUN |
| [Deployment](deployment.md) | Docker, systemd, Helm, TLS, firewall, multi-hop, scaling |
| [Monitoring](monitoring.md) | Prometheus metrics, pprof, Grafana examples |
| [Security](security.md) | Auth model, ECH, post-quantum, operational hardening |

## Configuration files

Server and client both accept `-config <path>` pointing at a TOML file. CLI
flags override the file, and the file overrides the defaults. Annotated
examples live outside `docs/`:

- [`configs/client.example.toml`](../configs/client.example.toml) - server
  list, `[selection]` policy, strategy, shaper, TLS, logging
- [`configs/server.example.toml`](../configs/server.example.toml) - listen
  address, certificate and key, logging
- [`internal/config/toml/MIGRATION.md`](../internal/config/toml/MIGRATION.md) -
  flag-to-TOML mapping and which flags are not covered yet

## Other references

- [`CHANGELOG.md`](../CHANGELOG.md) - what changed in each release
- [`deploy/helm/tiredvpn/README.md`](../deploy/helm/tiredvpn/README.md) - Helm
  chart values
- [`SECURITY.md`](../SECURITY.md) - how to report a vulnerability
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) - development workflow

These pages describe TiredVPN 1.5.1. Where a page documents behaviour that
changed in a specific release, it says so.
