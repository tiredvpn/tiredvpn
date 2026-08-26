# Deployment

Production deployment of TiredVPN 1.5.1 — packages, containers, Kubernetes,
TLS, firewall, multi-hop and capacity limits.

## What a release ships

A `v*` tag triggers `.github/workflows/release.yml`, which publishes:

| Artifact | Where |
|---|---|
| `tiredvpn-linux-amd64.tar.gz`, `tiredvpn-linux-arm64.tar.gz`, `checksums.txt` | GitHub Release |
| `.deb` and `.rpm` (amd64, arm64), built with nfpm | GitHub Release, plus the APT/YUM repos |
| APT repo (`reprepro`, suite `stable`), YUM repo (`createrepo`), GPG public key, `install.sh` | `gh-pages` → `https://tiredvpn.github.io/tiredvpn` |
| `tiredvpn/tiredvpn:latest` and `tiredvpn/tiredvpn:<version>`, `linux/amd64` + `linux/arm64` | Docker Hub |

The Helm chart is released separately: after a stable release, CI bumps
`deploy/helm/tiredvpn/Chart.yaml` (`appVersion` to the release version,
chart `version` by one patch), tags `chart-v<version>`, and
`.github/workflows/chart-release.yml` pushes the packaged chart to
`oci://ghcr.io/tiredvpn/charts`.

RPMs are signed when the CI GPG secret is present; local nfpm builds are
unsigned.

## Install from packages

### One-line installer

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/install.sh | sudo bash -s -- --port 443
```

`install.sh` adds the apt or yum repository and installs the package; on a host
with neither, it falls back to downloading the release tarball, verifying it
against `checksums.txt`, and installing the unit files by hand. It then runs
`tiredvpn-init`, which generates a secret and a self-signed EC certificate,
writes `/etc/tiredvpn/env` (mode 0600), starts the service, and prints a
`tired://` connection string with a QR code.

Flags: `--port N`, `--method repo|binary`, `--proxy-only`, `--force`.

TUN/full-VPN mode is on by default — the Android client needs it. `--proxy-only`
leaves the IP pool empty, which makes the server a SOCKS/HTTP proxy with no NAT.

### Debian/Ubuntu

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/tiredvpn-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/tiredvpn-archive-keyring.gpg] https://tiredvpn.github.io/tiredvpn/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/tiredvpn.list
sudo apt-get update && sudo apt-get install -y tiredvpn
sudo tiredvpn-init --port 443
```

### Fedora/RHEL

```bash
sudo tee /etc/yum.repos.d/tiredvpn.repo <<'EOF'
[tiredvpn]
name=TiredVPN
baseurl=https://tiredvpn.github.io/tiredvpn/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://tiredvpn.github.io/tiredvpn/gpg.key
EOF
sudo dnf install -y tiredvpn
sudo tiredvpn-init --port 443
```

### What the package installs

| Path | Purpose |
|---|---|
| `/usr/bin/tiredvpn` | the binary |
| `/usr/bin/tiredvpn-init` | first-run setup helper (idempotent, safe to re-run) |
| `/lib/systemd/system/tiredvpn.service` | the unit |
| `/etc/tiredvpn/env.example` | annotated environment template (config, `noreplace`) |
| `/etc/tiredvpn` | config directory, mode 0750 |

Package dependencies are `openssl` and `iproute2` (`iproute` on RPM).
`iproute2` is only used by `tiredvpn-init` for public-IP detection — NAT and
forwarding are done by the binary over netlink, so no `iptables` package is
needed.

## Docker

### Proxy mode

```bash
docker run -d \
  --name tiredvpn \
  --restart unless-stopped \
  -p 443:443/tcp \
  -p 443:443/udp \
  -v /etc/tiredvpn/certs:/certs:ro \
  tiredvpn/tiredvpn:latest \
  server \
  -listen :443 \
  -cert /certs/server.crt \
  -key /certs/server.key \
  -secret "${TIREDVPN_SECRET}"
```

The published image is built `FROM scratch` — the binary, CA certificates,
zoneinfo and a fake `index.html`, nothing else. Its entrypoint is `/tiredvpn`,
so `docker exec` into it is not possible; there is no shell. `EXPOSE` covers
443/tcp, 443/udp, 995/tcp and 995/udp (the last two are the default IPv6
listener).

An `alpine`-based `tun` build target exists with a shell and coreutils for
in-container troubleshooting. It is functionally identical otherwise; build it
with `docker build --target tun -t tiredvpn:tun .` if you want it. CI does not
publish it.

### Docker Compose

The repository ships `docker-compose.yml` with two services: `tiredvpn-server`
(proxy mode, default) and `tiredvpn-server-tun` (behind the `tun` profile).
Both mount `./certs` read-only and `./configs` at `/etc/tiredvpn`, and both
publish `${TIREDVPN_PORT:-443}` and `${TIREDVPN_PORT_V6:-995}` on TCP and UDP.

```bash
# proxy mode
TIREDVPN_SECRET=<secret> docker compose up -d

# TUN mode (adds NET_ADMIN, /dev/net/tun, ip_forward, -ip-pool)
TIREDVPN_SECRET=<secret> docker compose --profile tun up -d
```

The shipped compose file has no Redis service. Multi-client mode needs one —
add it yourself:

```yaml
services:
  tiredvpn-server:
    command:
      - "server"
      - "-listen"
      - ":443"
      - "-cert"
      - "/certs/server.crt"
      - "-key"
      - "/certs/server.key"
      - "-redis"
      - "redis:6379"
      - "-api-addr"
      - ":8080"
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

`-api-addr` only does something in multi-client mode: the management API and
`/metrics` are started from the Redis initialisation path
(`internal/server/server.go`). A server without `-redis` serves no HTTP API at
all, whatever `-api-addr` says. See [monitoring.md](monitoring.md).

### Build the image locally

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
docker build --build-arg VERSION=1.5.1 -t tiredvpn:local .
```

Without `--build-arg VERSION`, the binary reports `dev`.

## TUN mode in containers

Whenever `-ip-pool` is set, the binary flips `net.ipv4.ip_forward`, detects the
WAN interface, and installs `MASQUERADE` + `FORWARD` rules for the pool CIDR
directly over netlink into a dedicated nftables table
(`tiredvpn-nat-<sanitised-pool>`). With `-ip-pool-v6` it does the same in the
`ip6` family (`tiredvpn-nat6-*`, NAT66), picking the uplink from the IPv6 route
rather than the IPv4 one. No `iptables`, no entrypoint wrapper, nothing to NAT
by hand inside the container. See
[Server firewall and forwarding](../README.md#server-firewall-and-forwarding-required-for-tun-mode).

Whatever the runtime, a TUN server needs three things from the host: the
`/dev/net/tun` device, the `NET_ADMIN` capability, and a writable
`net.ipv4.ip_forward`.

### docker run

```bash
docker run -d \
  --name tiredvpn-tun \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -p 443:443/tcp \
  -p 443:443/udp \
  -v /etc/tiredvpn/certs:/certs:ro \
  tiredvpn/tiredvpn:latest \
  server \
  -listen :443 \
  -cert /certs/server.crt \
  -key /certs/server.key \
  -secret "${TIREDVPN_SECRET}" \
  -ip-pool 10.8.0.0/24
```

`-ip-pool` is what turns on TUN serving and tells the binary which CIDR to NAT.
A TUN client (`tiredvpn client -tun`) then gets an IP from that pool and its
traffic exits through the container's WAN interface.

NAT setup is non-fatal: a container without `CAP_NET_ADMIN` logs a warning and
comes up proxy-degraded rather than refusing to start. If TUN clients connect
but reach nothing, check the startup log for `NAT auto-config failed`.

### Kubernetes / Helm

The chart gates server TUN behind `server.tun.enabled`:

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn \
  --version 0.3.1 \
  --set server.tun.enabled=true \
  -f my-values.yaml
```

With `server.tun.enabled=true` the pod mounts `/dev/net/tun`, runs as UID 0
with `NET_ADMIN` and `NET_RAW` (or `privileged: true` when
`server.tun.privileged=true`), and uses `hostNetwork: true`. NAT happens
against the node's real interface, since `hostNetwork` puts the pod in the
node's network namespace.

The default image already handles TUN mode, so no image override is needed.
If you do want a different image for this pod, the keys are
`server.tun.image.{repository,tag,pullPolicy}` — there is no `server.image.*`
in `values.yaml`; the shared default is `global.image.*`.

One sharp edge: `net.ipv4.ip_forward` is an *unsafe* sysctl in Kubernetes. The
kubelet refuses it unless you either run the container `privileged: true` or
start the kubelet with `--allowed-unsafe-sysctls=net.ipv4.ip_forward`. With
`hostNetwork` and a host that already has forwarding on, the privileged path is
usually the least fiddly. See
[deploy/helm/tiredvpn/README.md](../deploy/helm/tiredvpn/README.md) for the full
value list and the chart's known limitations.

## TLS certificates

### Let's Encrypt

```bash
apt install certbot
certbot certonly --standalone -d your-server.com

tiredvpn server \
  -listen :443 \
  -cert /etc/letsencrypt/live/your-server.com/fullchain.pem \
  -key /etc/letsencrypt/live/your-server.com/privkey.pem \
  -secret <secret>
```

Auto-renew with a cron job:

```
0 0 1 * * certbot renew --quiet && systemctl restart tiredvpn
```

The unit has no `ExecReload`, so `systemctl reload` will not pick up a renewed
certificate — the process reads the key pair once at startup.

### Self-signed certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 3650 \
  -subj "/CN=your-server.com"
```

Self-signed works: the client does not validate the server certificate chain,
authentication is by shared secret. `tiredvpn-init` generates an EC certificate
this way. A real certificate matters only for the fake-website camouflage.

## Systemd

The packaged unit reads everything from `/etc/tiredvpn/env`:

```ini
ExecStart=/usr/bin/tiredvpn server -listen ${TIREDVPN_LISTEN} -cert ${TIREDVPN_CERT} -key ${TIREDVPN_KEY} -ip-pool ${TIREDVPN_IP_POOL}
```

The secret is never on the command line — the server falls back to
`TIREDVPN_SECRET` from the environment file, so it does not show up in
`ps`/`cmdline`. An empty `TIREDVPN_IP_POOL` expands to `-ip-pool ""`, which the
server treats as proxy-only mode. The unit sets
`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` and `LimitNOFILE=65536`.

Recognised environment variables:

| Variable | Meaning |
|---|---|
| `TIREDVPN_LISTEN` | listen address, `host:port` (empty host = all interfaces) |
| `TIREDVPN_CERT`, `TIREDVPN_KEY` | TLS key pair paths |
| `TIREDVPN_SECRET` | shared secret; fallback for `-secret` |
| `TIREDVPN_IP_POOL` | client IP pool CIDR; empty = proxy-only |
| `TIREDVPN_WAN_IFACE` | override the autodetected WAN interface for NAT |
| `TIREDVPN_API_TOKEN` | fallback for `-api-token` |
| `TIREDVPN_REDIS_DB`, `TIREDVPN_REDIS_PREFIX` | fallbacks for `-redis-db`, `-redis-prefix` |

### Hand-written unit

For a multi-client server with Redis and the management API:

```ini
# /etc/systemd/system/tiredvpn.service
[Unit]
Description=TiredVPN server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/tiredvpn/env
ExecStart=/usr/local/bin/tiredvpn server \
  -listen :443 \
  -cert /etc/tiredvpn/server.crt \
  -key /etc/tiredvpn/server.key \
  -redis 127.0.0.1:6379 \
  -api-addr 127.0.0.1:8080 \
  -ip-pool 10.8.0.0/24
Restart=always
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now tiredvpn
journalctl -u tiredvpn -f
```

Set `-api-token` (or `TIREDVPN_API_TOKEN`) whenever `-api-addr` is not on
loopback. Without it, anyone who can reach that address can create and delete
clients and read their secrets; the server logs a warning at startup in that
case but still serves.

## Firewall

Allow inbound traffic on the listening port, TCP and UDP:

```bash
# nftables
nft add rule inet filter input tcp dport 443 accept
nft add rule inet filter input udp dport 443 accept

# ufw
ufw allow 443/tcp
ufw allow 443/udp

# firewalld
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=443/udp
firewall-cmd --reload
```

With `-enable-v6` (default on) the server also listens on `-listen-v6`. Left
unset, that is `[::]` on the `-listen` port, so the rules above already cover it.
Set `-listen-v6` to put IPv6 on a different port, and open that port too.

If you use port hopping (`-port-range`), open the whole range:

```bash
nft add rule inet filter input udp dport 47000-47100 accept
nft add rule inet filter input tcp dport 47000-47100 accept
```

### Forwarding and NAT

For TUN mode, forwarding and NAT are automatic and cover both families:

- `-ip-pool` → `net.ipv4.ip_forward=1` plus `MASQUERADE` and `FORWARD` accept
  rules in the `ip` family;
- `-ip-pool-v6` → `net.ipv6.conf.all.forwarding=1` plus NAT66 in the `ip6`
  family, using the IPv6 uplink (falling back to the IPv4 one if the box has no
  IPv6 route).

Both are installed over netlink into per-pool nftables tables, so they coexist
with your own rules and with other instances on the same host. Both are
warn-and-continue on failure.

The packaged unit enables TUN by default (`TIREDVPN_IP_POOL=10.8.0.0/24`).
Opt out with `install.sh --proxy-only` / `tiredvpn-init --proxy-only`, or an
empty `TIREDVPN_IP_POOL`.

If a foreign `FORWARD` policy of `drop` is in place, the server logs a warning
at startup — its own accept rules live in a separate table and do not override
another table's policy.

## Multi-hop

Chain two servers so traffic exits through a second node:

```
Client → Server A (relay, censored country) → Server B (exit) → Internet
```

**Server B** (exit node, normal setup):

```bash
tiredvpn server \
  -listen :443 \
  -cert server-b.crt \
  -key server-b.key \
  -secret <upstream-secret>
```

**Server A** (relay):

```bash
tiredvpn server \
  -listen :443 \
  -cert server-a.crt \
  -key server-a.key \
  -secret <client-secret> \
  -upstream server-b.example.com:443 \
  -upstream-secret <upstream-secret>
```

**Client** connects only to Server A and does not need to know about Server B:

```bash
tiredvpn client \
  -server server-a.example.com:443 \
  -secret <client-secret>
```

`-upstream-secret` is mandatory with `-upstream`; the server refuses to start
without it.

Two relay knobs matter under load:

| Flag | Default | Effect |
|---|---|---|
| `-relay-idle-timeout` | `0` (= 90s) | force-closes silent relay→upstream TUN bridges so they stop holding admission slots and buffers |
| `-relay-upstream-buf` | `0` (= 512KB) | `SO_RCVBUF`/`SO_SNDBUF` in bytes for the TCP dial to the upstream; lower it to bound relay memory |

## Scaling and capacity limits

For high-traffic deployments:

- Run multiple server instances behind a load balancer. Sessions are per-connection,
  but the client registry is shared only through Redis — use a central Redis for
  multi-client mode, and give each instance its own `-redis-db` or `-redis-prefix`
  if they must share one Redis without sharing state.
- Scrape `/metrics` with Prometheus (see [monitoring.md](monitoring.md)).
- Keep `LimitNOFILE=65536` in the unit.

```bash
# Open file descriptors for the running server
ls /proc/$(pgrep -x tiredvpn)/fd | wc -l
```

### Admission control

Unbounded accept was how the server used to run out of memory under DPI-driven
reconnect storms. Three ceilings bound it:

| Flag | Default | Effect |
|---|---|---|
| `-max-conns` | `0` (= 4096) | maximum in-flight incoming connections; excess is dropped |
| `-node-max-clients` | `0` (off) | cap on distinct authenticated clients on this node |
| `-node-max-bytes` | `0` (off) | cap on bytes carried per window on this node |
| `-node-window` | `1h` | the sliding window `-node-max-bytes` is measured over |

`-node-max-clients` counts client identities. Transports that authenticate
against a single shared secret carry no client id and are not counted, so the
real number of users on the node can exceed the cap. The node ceilings surface
as `tiredvpn_node_*` metrics — alert on `tiredvpn_node_ceiling_used` before
`tiredvpn_node_refused_total` starts moving.

`-node-max-bytes` is the ceiling that means something on a relay, where the
peers are downstream nodes rather than people.

## IPv6 and dual-stack

The server listens on IPv6 by default:

| Flag | Default |
|---|---|
| `-enable-v6` | `true` |
| `-listen-v6` | empty — `[::]` on the `-listen` port |
| `-dual-stack` | `true` |
| `-ip-pool-v6` | empty (in-tunnel IPv6 disabled) |

Two different things are called "IPv6" here:

- **Transport** — the client reaching the server over IPv6. Controlled by
  `-enable-v6`/`-listen-v6` on the server and `-server-v6`/`-prefer-ipv6` on the
  client. On by default at both ends.
- **In-tunnel IPv6** — IPv6 traffic carried inside the tunnel. Needs
  `-ip-pool-v6` on the exit; without it the client's dual-stack negotiation
  fails and the session stays IPv4-only.

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret> \
  -ip-pool 10.8.0.0/24 \
  -ip-pool-v6 fd00:10:8::/64
```

Since 1.5.0 the client's `-tun-ipv6` defaults to `dual`, which rejects outbound
IPv6 for the life of the tunnel when the exit cannot carry it — otherwise every
application with a working IPv6 default route would leave the VPN and hand out
the host's real address. **Upgrade exits and relays before clients**: an exit
that predates dual-stack answers a `0x04` client without a flags byte, which
costs a 300 ms grace period per connect and logs a warning.

Open the IPv6 listener in the firewall:

```bash
nft add rule inet filter input ip6 nexthdr tcp tcp dport 995 accept
nft add rule inet filter input ip6 nexthdr udp udp dport 995 accept
```

## Runbook: upgrade

*Illustrative — the procedure below has not been executed as part of writing
this page. Verify each step on a staging node before running it in production.*

**Preconditions:** a maintenance window (the service restarts and drops live
sessions), root on the target host, the release version to install, and a
recorded current version (`tiredvpn -version`) to roll back to.

Package installs:

```bash
# 1. Record what is running now
tiredvpn -version
systemctl is-active tiredvpn

# 2. Upgrade
apt-get update && apt-get install --only-upgrade tiredvpn   # or: dnf upgrade tiredvpn

# 3. Verify
tiredvpn -version
systemctl status tiredvpn
journalctl -u tiredvpn -n 50 --no-pager
```

Checks that the upgrade worked:

- the startup log line reports the new version;
- with TUN enabled, the log shows `NAT: using WAN interface <iface> for pool <cidr>`
  and no `NAT auto-config failed`;
- with TUN enabled, `ip addr show tiredvpn0` shows the interface up with the
  configured `-tun-ip`, and `nft list ruleset` contains the per-pool
  `tiredvpn-nat-*` table;
- a client connects and reaches the internet through the tunnel;
- in multi-client mode, `curl -fsS http://127.0.0.1:8080/health` returns
  `{"status":"healthy",...}` (add `-H "Authorization: Bearer <token>"` when
  `-api-token` is set).

**Rollback** — pin the previous version:

```bash
apt-get install -y --allow-downgrades tiredvpn=<previous-version>
# or
dnf downgrade tiredvpn-<previous-version>
systemctl restart tiredvpn
tiredvpn -version
```

Binary installs: keep the previous binary, since a running executable cannot be
overwritten in place.

```bash
systemctl stop tiredvpn
mv /usr/bin/tiredvpn /usr/bin/tiredvpn.prev
install -m 0755 ./tiredvpn-linux-amd64 /usr/bin/tiredvpn
systemctl start tiredvpn
# rollback: systemctl stop tiredvpn && mv /usr/bin/tiredvpn.prev /usr/bin/tiredvpn && systemctl start tiredvpn
```

Take the binary from the GitHub Release tarball and check it against
`checksums.txt` rather than from a local build — a local build is not the
artifact anyone else is running.

Docker:

```bash
docker compose pull && docker compose up -d
# rollback: pin the previous tag instead of :latest and re-run
```

Helm:

```bash
helm upgrade my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn --version <chart-version> -f my-values.yaml
helm rollback my-tiredvpn
```
