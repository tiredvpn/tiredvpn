# Getting Started

This guide walks you through deploying a TiredVPN server and connecting your
first client.

There are two routes. The **packaged install** does everything for you and is
what you want for a real server. The **manual install** is the same steps done
by hand, and is worth reading if you are packaging TiredVPN yourself, running
it without systemd, or debugging.

## Prerequisites

- A Linux server with a public IP address
- Your chosen port open for both TCP and UDP (443 by default; TLS rides TCP,
  QUIC rides UDP)
- `systemd`, `curl` and `openssl` for the packaged install
- Go 1.26+ only if you build from source

You do not need a CA-signed certificate. The server generates a self-signed one
and serves a fake website to anyone who fails authentication.

## Packaged install (recommended)

### One-liner

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/install.sh | sudo bash -s -- --port 443
```

The installer adds the signed apt or yum repository and installs the native
package; on a host with neither, it falls back to downloading the release
binary and installing the unit file by hand. It then runs `tiredvpn-init`,
which generates a secret and certificate, starts the service, and prints a
`tired://` connection string with a QR code for the mobile app.

Useful flags: `--port N`, `--proxy-only` (SOCKS proxy only, no TUN and no NAT),
`--method repo|binary`, `--force` (regenerate the secret and certificate).

### Debian/Ubuntu

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/tiredvpn-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/tiredvpn-archive-keyring.gpg] https://tiredvpn.github.io/tiredvpn/apt stable main" | sudo tee /etc/apt/sources.list.d/tiredvpn.list
sudo apt update && sudo apt install tiredvpn
sudo tiredvpn-init
```

### Fedora/RHEL

```bash
sudo tee /etc/yum.repos.d/tiredvpn.repo >/dev/null <<'EOF'
[tiredvpn]
name=TiredVPN
baseurl=https://tiredvpn.github.io/tiredvpn/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://tiredvpn.github.io/tiredvpn/gpg.key
EOF
sudo dnf install tiredvpn && sudo tiredvpn-init
```

The package installs the service **stopped**. `tiredvpn-init` is what finishes
setup, and it is idempotent - re-running it will not clobber an existing secret
or certificate unless you pass `--force`.

### What the package configures

- `/usr/bin/tiredvpn`, `/usr/bin/tiredvpn-init`, and a systemd unit
- `/etc/tiredvpn/env` (mode 0600) with the secret and the listen port
- `/etc/tiredvpn/server.crt` and `server.key`, self-signed EC
- TUN mode on by default: `TIREDVPN_IP_POOL=10.8.0.0/24`. The Android app
  always uses native TUN, so this is what makes it work on a fresh install.
- `net.ipv4.ip_forward` plus `MASQUERADE`/`FORWARD` nftables rules for that
  pool, installed by the binary itself over netlink on every start

Change the pool with `tiredvpn-init --ip-pool <CIDR>`; turn TUN off with
`--proxy-only`. The automatic NAT setup is IPv4-only - see
[deployment.md](deployment.md) for IPv6.

`tiredvpn-init` prints the connection string and the secret at the end. Keep
them; the client needs the secret.

## Manual install

### 1. Get the binary

Pre-built release:

```bash
base=https://github.com/tiredvpn/tiredvpn/releases/latest/download
curl -LO $base/tiredvpn-linux-amd64.tar.gz
curl -LO $base/checksums.txt
grep tiredvpn-linux-amd64.tar.gz checksums.txt | sha256sum -c -
tar xzf tiredvpn-linux-amd64.tar.gz
sudo install -m 0755 tiredvpn-linux-amd64 /usr/local/bin/tiredvpn
```

From source:

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
make build          # -> ./tiredvpn
```

Docker:

```bash
docker pull tiredvpn/tiredvpn:latest
```

### 2. Generate a shared secret

```bash
openssl rand -hex 32
# example output: a3f1c9e2b7d05481f6e3a2c8d9b04572e1f8c3a6d7e2b5f9081c4d3e6a7b8c90
```

Keep this secret; you will use it on both the server and the client.

### 3. Generate a TLS certificate

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 365 -nodes -keyout server.key -out server.crt \
  -subj "/CN=your-server.com"
```

For production use Let's Encrypt or any CA-signed certificate. See
[deployment.md](deployment.md) for details.

### 4. Start the server

```bash
./tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <your-secret>
```

The server now:

- Accepts TLS (TCP) on `:443` and QUIC (UDP) on `:443`
- Also listens on `[::]:995` (`-listen-v6`, IPv6 is on by default)
- Serves a fake website to unauthenticated visitors, over HTTP/1.1 or HTTP/2
  depending on the ALPN the peer negotiated
- Authenticates clients by HMAC-verified secret

> This command starts a **proxy-only** server. A TUN client - including the
> Android app - also needs `-ip-pool` plus host forwarding and NAT. Add
> `-ip-pool 10.8.0.0/24` and the server installs the forwarding and NAT rules
> itself on start; without `CAP_NET_ADMIN` it logs a warning and comes up
> proxy-degraded rather than refusing to start. See [server.md](server.md) and
> [deployment.md](deployment.md).

To verify the server is running:

```bash
curl -sk https://localhost:443/
# returns the fake website content
```

## Connect a client (SOCKS5 proxy mode)

On your client machine:

```bash
./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -listen 127.0.0.1:1080
```

This starts a local SOCKS5 proxy on `127.0.0.1:1080`. Point any application
to it:

```bash
curl --socks5 127.0.0.1:1080 https://api.ipify.org
# should return the server's IP address
```

In Firefox: Settings → Network → Manual proxy → SOCKS5 `127.0.0.1`, port 1080.

The client probes the available strategies and picks one. If it gets blocked
mid-session, the client falls back to another without dropping connections.
`-list` prints the strategies; `-strategy <id>` pins one.

## Connect a client (full VPN / TUN mode)

TUN mode routes system traffic through the VPN. It needs `root` or
`CAP_NET_ADMIN`.

```bash
sudo ./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -tun \
  -tun-routes 0.0.0.0/0
```

This creates a `tiredvpn0` interface and adds a default route through it. The
MTU is probed end-to-end and capped at `-tun-mtu` (`-auto-mtu`, on by default).

To route only specific subnets (split tunnel):

```bash
sudo ./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -tun \
  -tun-ipv6 off \
  -tun-routes 10.0.0.0/8,192.168.100.0/24
```

### IPv6 in the tunnel

`-tun-ipv6` defaults to `dual` since 1.5.0:

- `dual` - IPv6 goes through the tunnel when the exit was started with
  `-ip-pool-v6`. When it was not, outbound IPv6 is rejected for the life of the
  tunnel, so applications fall back to IPv4 instead of reaching the internet
  around the VPN with your real address.
- `block` - never ask the exit for IPv6, just reject it.
- `off` - IPv4-only tunnel, host IPv6 left alone. This is the pre-1.5.0
  behaviour and it does bypass the VPN on a dual-stack host.

`dual` sends *all* IPv6 into the tunnel, including destinations you routed
around it on IPv4 - which is why the split-tunnel example above sets `off`.
The blocking half is Linux-only; on macOS it warns instead of hiding the gap.

## Use a config file

Anything long-lived is easier to keep in TOML. CLI flags override the file, the
file overrides the defaults, and a flag only counts as set if you actually
passed it.

```toml
# /etc/tiredvpn/client.toml
[server]
address = "vpn.example.org"
port = 443

[strategy]
mode = "reality"

[logging]
level = "info"
```

```bash
./tiredvpn client -config /etc/tiredvpn/client.toml -secret <your-secret>
```

Unknown keys are rejected, so a typo fails at startup. `-secret` and the
`-tun-*` flags are not in the schema yet - see
[`internal/config/toml/MIGRATION.md`](../internal/config/toml/MIGRATION.md) for
what is covered.

## Give the client several servers

A server list is config-file only; no flag takes more than one address.
`[server]` and `[[servers]]` are mutually exclusive, and passing `-server`
collapses the list to one entry.

```toml
[[servers]]
name = "ams"
address = "203.0.113.10"
port = 443
address_v6 = "2001:db8::10"
weight = 100

[[servers]]
name = "fra"
address = "203.0.113.20"
port = 443
weight = 50

[selection]
policy = "priority"      # priority (list order) | latency | weighted
family = "prefer_v6"     # prefer_v6 | prefer_v4 | v6_only | v4_only
failure_threshold = 2
cooldown = "1m"
min_dwell = "5m"
```

A candidate that fails to connect twice in a row is parked with an exponential
cooldown, and the preferred one is retried on a reconnect that would have
happened anyway. Background health checks are off by default. Full field list:
[`configs/client.example.toml`](../configs/client.example.toml) and
[client.md](client.md).

## Next steps

- [Server configuration reference](server.md) - all server flags
- [Client configuration reference](client.md) - all client flags, evasion options
- [Admin and client management](admin.md) - multi-client mode, REST API, QR codes
- [DPI bypass strategies](strategies.md) - how the adaptive engine works
- [Production deployment](deployment.md) - Docker, systemd, Helm, multi-hop
- [Security model](security.md) - auth, ECH, post-quantum crypto
