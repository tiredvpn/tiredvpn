# tiredvpn Helm chart

Helm chart for deploying [tiredvpn](https://github.com/tiredvpn/tiredvpn-oss) — DPI-resistant VPN — on Kubernetes. The chart can deploy the server (exit node) and/or the client (SOCKS5 proxy or TUN tunnel) from a single release.

Chart version 0.3.2, `appVersion` 1.7.0.

## Install

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn \
  --version 0.3.1 -f my-values.yaml
```

Or from a local checkout:

```bash
cd deploy/helm/tiredvpn
helm install my-tiredvpn . -f my-values.yaml
```

The optional Redis subchart is vendored in `charts/` and pinned by
`Chart.lock`, so a local install needs no `helm repo add`. Run
`helm dependency update` only when you want to refresh it — that does require
the bitnami repository.

Requirements: Kubernetes ≥ 1.25, Helm ≥ 3.8.

## Examples

### 1. Minimal server (single-client)

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.create=true \
  --set-file server.tls.cert=server.crt \
  --set-file server.tls.key=server.key \
  --set server.auth.secret="$(openssl rand -hex 32)" \
  --set server.config.api.enabled=false
```

`server.config.api.enabled=false` is deliberate here — see
[Known limitations](#known-limitations). Without Redis the server starts no
HTTP API, and the chart's default `/health` probes would never pass.

### 2. Multi-client server with Redis

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.existingSecret=vpn-tls \
  --set server.auth.mode=external \
  --set redis.enabled=true \
  --set server.autoscaling.enabled=true \
  --set server.metrics.serviceMonitor.enabled=true
```

After startup, add clients via the admin API (`-api`, `-server` and `-name` are
all required):

```bash
kubectl exec deploy/vpn-tiredvpn-server -- /tiredvpn admin add \
  -api http://127.0.0.1:8080 -server vpn.example.com:443 -name alice
```

The published image is `FROM scratch` with entrypoint `/tiredvpn`; there is no
shell, so `kubectl exec` must invoke the binary directly as above.

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
      maxPorts: 50
      interval: 60s
      strategy: random
    quic:
      sniReassembly: true
EOF
```

`server.config.ipv6.enabled` and `server.config.ipv6.dualStack` are already
`true` by default, so the server listens on `[::]:995` as well as `:443`.
In-tunnel IPv6 (`-ip-pool-v6`) is not exposed through `config.*` — pass it via
`server.extraArgs`.

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

The SOCKS Deployment is probed on a TCP socket, so it does not depend on the
API being enabled.

### 5. Client in TUN mode (DaemonSet, tunnels node traffic)

The default `tiredvpn/tiredvpn` image works as-is — the client configures the TUN device (interface, IP, routes, MSS clamping) itself via netlink/nftables, no `ip`/`iptables` binaries needed. `client.tun.image.repository` is only for overriding to a different image on this DaemonSet specifically (e.g. a debug-shell variant).

```bash
helm install vpn-tunnel deploy/helm/tiredvpn -f - <<EOF
server: { enabled: false }
client:
  enabled: true
  mode: tun
  server: { existingSecret: vpn-credentials }
  config:
    api: { enabled: false }
  tun:
    routes: "0.0.0.0/0"
    usePrivileged: false   # NET_ADMIN+NET_RAW caps instead of privileged
EOF
```

`client.config.api.enabled` is turned off on purpose: the DaemonSet probes
`/health`, which the client does not serve. See
[Known limitations](#known-limitations).

## values structure

| Section | Description |
|---|---|
| `global.image.{repository, tag, pullPolicy}` | Shared image. `tag` empty = chart `appVersion` |
| `global.imagePullSecrets` | List of `kubernetes.io/dockerconfigjson` Secret references |
| `nameOverride`, `fullnameOverride` | Resource naming; default is the release name |
| `commonLabels`, `commonAnnotations` | Applied to all pods/objects |
| `serviceAccount.{create, name, annotations, automount}` | One SA shared by server and client |
| `server.enabled`, `server.replicaCount` | Server toggle and replica count |
| `server.config.*` | Binary CLI flags: `listen`, `listenV6`, `ipv6`, `quic`, `portHopping`, `tun`, `upstream`, `fakeRoot`, `api`, `pprof`, `debug` |
| `server.tun.{enabled, hostNetwork, privileged, capabilities, image}` | Server TUN exit-node mode: `/dev/net/tun`, root, `ip_forward` sysctl |
| `server.tls.{existingSecret, create, cert, key}` | TLS certificates: existing Secret or inline PEM |
| `server.auth.{mode, secret, tokens, existingSecret, existingSecretKey}` | Authentication: `secret` / `tokens` / `external` |
| `server.redis.addr` | External Redis address (used when the bitnami subchart is off) |
| `server.tomlConfig` | Alternative to `config.*` — raw TOML mounted via ConfigMap |
| `server.service.{main, api}` | Two Services: main (TCP+UDP, LoadBalancer by default) and api (ClusterIP) |
| `server.{resources, podSecurityContext, securityContext, nodeSelector, tolerations, affinity, topologySpreadConstraints, priorityClassName, podAnnotations, podLabels}` | Standard pod settings |
| `server.{extraEnv, extraEnvFrom, extraVolumes, extraVolumeMounts, extraArgs}` | Escape hatches |
| `server.pdb.{enabled, minAvailable}` | PodDisruptionBudget |
| `server.networkPolicy.{enabled, allowedMonitoringNamespaces, allowedFromMain, allowAllExternal}` | NetworkPolicy (ingress main+api, egress DNS+world) |
| `server.metrics.serviceMonitor.*` | Prometheus ServiceMonitor scraping `/metrics` on the `api` port |
| `server.autoscaling.*` | HPA — **requires** a shared Redis backend |
| `client.enabled`, `client.mode` | `socks` (Deployment) \| `tun` (DaemonSet) \| `both` |
| `client.server.{address, secret, existingSecret, existingSecretAddressKey, existingSecretSecretKey}` | VPN server address + secret |
| `client.config.*` | CLI flags: `debug`, `strategy`, `cover`, `fallback`, `quic`, `ech`, `pq`, `rttMasking`, `ipv6`, `portHop`, `adaptive`, `api`, `pprof` |
| `client.tomlConfig` | Alternative to `config.*` |
| `client.socks.{replicaCount, listen, httpListen, service, resources, podSecurityContext, securityContext, pdb, ...}` | SOCKS mode |
| `client.tun.{name, ip, peerIp, mtu, routes, hostNetwork, usePrivileged, image, updateStrategy, resources, nodeSelector, ...}` | TUN mode |
| `client.{extraEnv, extraEnvFrom, extraVolumes, extraVolumeMounts, extraArgs}` | Shared by both client modes |
| `client.metrics.serviceMonitor.*` | SOCKS mode only (via the `api` port) |
| `client.networkPolicy.{enabled, allowedClientNamespaces, allowedClientPodSelectors, allowAllEgress}` | NetworkPolicy for SOCKS |
| `redis.{enabled, architecture, auth, master}` | bitnami/redis dependency; when enabled and `server.redis.addr` is empty, the server is wired to `<release>-redis-master:6379` automatically |

Full value list with defaults: see [values.yaml](./values.yaml) (each field has an inline comment).

## CLI flags ↔ values

The chart renders binary args from `server.config.*` / `client.config.*` (see `_helpers.tpl`). For a flag not covered by values:

- `server.extraArgs` / `client.extraArgs` — appended to args (`extraArgs: ["-foo", "bar"]`);
- `server.tomlConfig` / `client.tomlConfig` — replaces all CLI flags with a TOML config (see `configs/server.example.toml` in the main repo).

Flags added in 1.5.0 have no `config.*` key yet and need one of the two escape
hatches: `-ip-pool-v6` (server, in-tunnel IPv6), `-tun-ipv6` (client, IPv6
policy while the tunnel is up), `-server-policy` and the `[[servers]]` list
(client, multi-endpoint failover — TOML only), `-api-token` (server, bearer
auth on the management API), `-max-conns`, `-node-max-clients`,
`-node-max-bytes` (server, admission control).

## Known limitations

Verified against the templates and `values.yaml` at chart 0.3.1. Each of these
is a chart gap, not a binary bug.

- **`/health` probes without Redis never pass.** `server.config.api.enabled`
  defaults to `true`, which switches the server Deployment to HTTP probes on
  `/health`. The binary starts its HTTP API only in multi-client mode
  (`-redis`), so a server with neither `redis.enabled=true` nor
  `server.redis.addr` set listens on nothing at that port and the pod never
  becomes ready. Set `server.config.api.enabled=false`, or enable Redis.
- **The client TUN DaemonSet probes an endpoint the client does not serve.**
  With `client.config.api.enabled=true`, `client-daemonset-tun.yaml` probes
  `/health`; the client's API server registers `/metrics` only. Leave
  `client.config.api.enabled=false` in `tun` mode, or the DaemonSet pods stay
  NotReady. The SOCKS Deployment is unaffected — it uses TCP probes.
- **`server.config.api.enabled` also has no auth.** The chart has no value for
  `-api-token` and renders `-api-addr :8080`, which binds all interfaces. Any
  pod that can reach the api Service can create and delete clients and read
  their secrets. Enable `server.networkPolicy.enabled`, and pass `-api-token`
  through `server.extraArgs` plus `server.extraEnv`.
- **ServiceMonitors carry no credentials.** If you do set `-api-token`, the
  rendered ServiceMonitor has no `authorization` block; scraping will 401.
- **`values.yaml` overstates the client API.** Its comment says
  `api.enabled` "exposes /metrics, /health" — the client serves `/metrics` only.
- There is no `server.image.*`. The server uses `global.image.*`; only
  `server.tun.image.*` overrides it, and only for the TUN pod.

## Verify before installing

```bash
helm lint deploy/helm/tiredvpn -f deploy/helm/tiredvpn/ci/server-minimal-values.yaml
helm template my-release deploy/helm/tiredvpn -f deploy/helm/tiredvpn/ci/server-minimal-values.yaml | kubectl apply --dry-run=client -f -
```

`ci/` contains fixtures for typical scenarios — `server-minimal`, `server-redis`, `server-porthop`, `server-tun`, `client-socks`, `client-tun`, `both`. `.github/workflows/chart-release.yml` runs `helm lint` and `helm template` over every one of them before packaging, so a change that breaks any fixture blocks the chart release.

## Compatibility

- Helm: 3.8+
- Kubernetes: 1.25+ (uses `policy/v1` PDB, `autoscaling/v2` HPA, `networking.k8s.io/v1` NetworkPolicy)
- tiredvpn: `appVersion` in Chart.yaml, currently `1.7.0`. CI keeps it in step with the application release — a stable `v*` tag bumps `appVersion` to that version and patch-bumps the chart `version`.

## License

AGPL-3.0 (inherited from the main project).
