# tiredvpn Helm chart

Helm chart for deploying [tiredvpn](https://github.com/tiredvpn/tiredvpn-oss) — DPI-resistant VPN — on Kubernetes. The chart can deploy the server (exit node) and/or the client (SOCKS5 proxy or TUN tunnel) from a single release.

## Install

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn \
  --version 0.1.0 -f my-values.yaml
```

Or from a local checkout:

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami    # for the optional Redis subchart
cd deploy/helm/tiredvpn
helm dependency update
helm install my-tiredvpn . -f my-values.yaml
```

Requirements: Kubernetes ≥ 1.25, Helm ≥ 3.8.

## Examples

### 1. Minimal server (single-client)

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.create=true \
  --set-file server.tls.cert=server.crt \
  --set-file server.tls.key=server.key \
  --set server.auth.secret="$(openssl rand -hex 32)"
```

### 2. Multi-client server with Redis

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.existingSecret=vpn-tls \
  --set server.auth.mode=external \
  --set redis.enabled=true \
  --set server.autoscaling.enabled=true \
  --set server.metrics.serviceMonitor.enabled=true
```

After startup, add clients via the admin API:

```bash
kubectl exec deploy/vpn-tiredvpn-server -- /tiredvpn admin add \
  -api http://127.0.0.1:8080 -server vpn.example.com:443
```

### 3. Server with port-hopping and IPv6 dual-stack

```bash
helm install vpn deploy/helm/tiredvpn -f - <<EOF
server:
  tls: { existingSecret: vpn-tls }
  auth: { mode: secret, secret: "$(openssl rand -hex 32)" }
  config:
    portHopping:
      enabled: true
      range: "47000-47100"
      interval: 60s
      strategy: random
    quic:
      sniReassembly: true
EOF
```

### 4. Client in SOCKS5 mode (reachable by other pods in the cluster)

```bash
helm install proxy deploy/helm/tiredvpn -f - <<EOF
server: { enabled: false }
client:
  enabled: true
  mode: socks
  server:
    address: "vpn.example.com:443"
    secret: "<shared-secret>"
  socks:
    replicaCount: 2
    pdb: { enabled: true }
EOF
```

From any pod: `curl -x socks5h://proxy-tiredvpn-client-socks:1080 https://ifconfig.me`.

### 5. Client in TUN mode (DaemonSet, tunnels node traffic)

The default `tiredvpn/tiredvpn` image works as-is - the client configures the TUN device (interface, IP, routes, MSS clamping) itself via netlink/nftables, no `ip`/`iptables` binaries needed. `client.tun.image.repository` is only for overriding to a different image on this DaemonSet specifically (e.g. a debug-shell variant).

```bash
helm install vpn-tunnel deploy/helm/tiredvpn -f - <<EOF
server: { enabled: false }
client:
  enabled: true
  mode: tun
  server: { existingSecret: vpn-credentials }
  tun:
    routes: "0.0.0.0/0"
    usePrivileged: false   # NET_ADMIN+NET_RAW caps instead of privileged
    image:
      repository: myorg/tiredvpn-tun
      tag: 1.1.3
EOF
```

## values structure

| Section | Description |
|---|---|
| `global.image.*` | Registry, tag (defaults to chart `appVersion`), pullPolicy |
| `serviceAccount.*` | One SA per release |
| `server.enabled` | Server toggle |
| `server.config.*` | Binary CLI flags (listen, ipv6, quic, portHopping, tun, upstream, fakeRoot, api, pprof, debug) |
| `server.tls.{existingSecret, create, cert, key}` | TLS certificates: existing Secret or inline PEM |
| `server.auth.{mode, secret, tokens, existingSecret}` | Authentication: `secret` / `tokens` / `external` |
| `server.redis.addr` | External Redis address (used when the bitnami subchart is not enabled) |
| `server.tomlConfig` | Alternative to `config.*` — raw TOML mounted via ConfigMap |
| `server.service.{main, api}` | Two separate Services: main (TCP+UDP/LoadBalancer) and api (ClusterIP) |
| `server.{resources, podSecurityContext, securityContext, nodeSelector, ...}` | standard K8s pod settings |
| `server.pdb.enabled` | PodDisruptionBudget |
| `server.networkPolicy.enabled` | NetworkPolicy (ingress main+api, egress DNS+world) |
| `server.metrics.serviceMonitor.enabled` | Prometheus ServiceMonitor scraping `/metrics` on the api port |
| `server.autoscaling.enabled` | HPA — **requires** a shared Redis backend |
| `client.enabled` | Client toggle |
| `client.mode` | `socks` (Deployment) \| `tun` (DaemonSet) \| `both` |
| `client.server.{address, secret, existingSecret}` | VPN server address + secret |
| `client.config.*` | CLI flags: strategy, cover, quic, ech, pq, rttMasking, ipv6, portHop, adaptive, api, pprof |
| `client.tomlConfig` | Alternative to `config.*` |
| `client.socks.*` | SOCKS mode: listen / replicaCount / service / resources / PDB |
| `client.tun.*` | TUN mode: name / ip / peerIp / mtu / routes / usePrivileged / image |
| `client.metrics.serviceMonitor.enabled` | SOCKS mode only (also via the `api` port) |
| `client.networkPolicy.enabled` | NetworkPolicy for SOCKS |
| `redis.enabled` | Pull in bitnami/redis as a dependency; if enabled and `server.redis.addr` is empty, the server is wired to `<release>-redis-master:6379` automatically |

Full value list with defaults: see [values.yaml](./values.yaml) (each field has an inline comment).

## CLI flags ↔ values

The chart renders binary args from `server.config.*` / `client.config.*` (see `_helpers.tpl`). For a flag not covered by values:

- `server.extraArgs` / `client.extraArgs` — appended to args (`extraArgs: ["-foo", "bar"]`);
- `server.tomlConfig` / `client.tomlConfig` — replaces all CLI flags with a TOML config (see `configs/server.example.toml` in the main repo).

## Verify before installing

```bash
helm lint deploy/helm/tiredvpn -f ci/server-minimal-values.yaml
helm template my-release deploy/helm/tiredvpn -f ci/server-minimal-values.yaml | kubectl apply --dry-run=client -f -
```

`ci/` contains fixtures for typical scenarios (server-minimal, server-redis, server-porthop, client-socks, client-tun, both); they're used for lint checks in CI and locally.

## Compatibility

- Helm: 3.8+
- Kubernetes: 1.25+ (uses `policy/v1` PDB, `autoscaling/v2` HPA, `networking.k8s.io/v1` NetworkPolicy)
- tiredvpn: matches `appVersion` in Chart.yaml (default `1.3.23`)

## License

AGPL-3.0 (inherited from the main project).
