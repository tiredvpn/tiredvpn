# Deployment

This guide covers production deployment of TiredVPN.

## Docker (recommended)

### Single container

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

### Docker Compose with Redis (multi-client)

```yaml
# docker-compose.yml
version: "3.8"

services:
  tiredvpn:
    image: tiredvpn/tiredvpn:latest
    ports:
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./certs:/certs:ro
      - ./www:/www:ro
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
      - "-fake-root"
      - "/www"
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

```bash
TIREDVPN_SECRET=<secret> docker compose up -d
```

This runs the server in SOCKS5/proxy mode - the default image egresses client
traffic itself, no TUN device involved. If you want full TUN tunnelling
(`-ip-pool`), the default image will not work: it is a scratch build with no
`iptables`, so it cannot set up NAT. See [TUN mode in containers](#tun-mode-in-containers)
below for the tun image and the extra container privileges it needs.

### Build the image locally

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
docker build -t tiredvpn:local .
```

## TUN mode in containers

The default image (`tiredvpn/tiredvpn:latest`) is a minimal scratch build aimed
at proxy mode. It has no `iptables` and no shell, so it cannot create the
`MASQUERADE`/`FORWARD` rules a TUN server needs. For server-side TUN inside a
container, build and run the `tun` target instead.

The `tun` image (`tiredvpn:tun`) is Alpine-based with `iptables`. Its entrypoint
sets up forwarding on its own: it flips `net.ipv4.ip_forward`, detects the WAN
interface, and installs `MASQUERADE` + `FORWARD` rules for the `-ip-pool` CIDR
you pass. You do not NAT by hand inside the container - that manual dance is only
for bare-metal/host setups (see [Server firewall and forwarding](../README.md#server-firewall-and-forwarding-required-for-tun-mode)).
If WAN auto-detection picks the wrong interface, override it with the
`TIREDVPN_WAN_IFACE` env var.

Whatever the runtime, a TUN server needs three things from the host: the
`/dev/net/tun` device, the `NET_ADMIN` capability, and a writable
`net.ipv4.ip_forward`.

Build the tun image:

```bash
docker build --target tun -t tiredvpn:tun .
```

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
  tiredvpn:tun \
  server \
  -listen :443 \
  -cert /certs/server.crt \
  -key /certs/server.key \
  -secret "${TIREDVPN_SECRET}" \
  -ip-pool 10.8.0.0/24
```

The `-ip-pool` flag is what turns on TUN serving and tells the entrypoint which
CIDR to NAT. Once the container is up, a TUN client (`tiredvpn client -tun`) gets
an IP from that pool and its traffic exits through the container's WAN interface.

### docker-compose

The compose file ships a `tun` profile so the proxy-mode default stays
unaffected. Bring it up explicitly:

```bash
TIREDVPN_SECRET=<secret> docker compose --profile tun up -d
```

The profiled service uses the `tun` image and already carries the right
settings - `cap_add: NET_ADMIN`, `devices: /dev/net/tun`, and
`sysctls: net.ipv4.ip_forward=1` - plus the `-ip-pool` flag in its command. The
entrypoint handles NAT from there.

```yaml
services:
  tiredvpn-tun:
    build:
      context: .
      target: tun
    image: tiredvpn:tun
    profiles: ["tun"]
    ports:
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./certs:/certs:ro
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    command:
      - "server"
      - "-listen"
      - ":443"
      - "-cert"
      - "/certs/server.crt"
      - "-key"
      - "/certs/server.key"
      - "-secret"
      - "${TIREDVPN_SECRET}"
      - "-ip-pool"
      - "10.8.0.0/24"
    restart: unless-stopped
```

### Kubernetes / Helm

The chart gates server TUN behind `server.tun.enabled`:

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn \
  --set server.tun.enabled=true \
  --set server.image.repository=tiredvpn \
  --set server.image.tag=tun \
  -f my-values.yaml
```

With `server.tun.enabled=true` the pod mounts `/dev/net/tun`, runs with
`NET_ADMIN` (or `privileged: true` where the cap alone is not enough), and uses
`hostNetwork: true`. NAT happens against the node's real interface, since
`hostNetwork` puts the pod in the node's network namespace - the same WAN
detection and `MASQUERADE` the entrypoint does on bare metal.

One sharp edge: `net.ipv4.ip_forward` is an *unsafe* sysctl in Kubernetes. The
kubelet refuses it unless you either run the container `privileged: true` (which
inherits a writable, already-on `ip_forward` from the host netns) or start the
kubelet with `--allowed-unsafe-sysctls=net.ipv4.ip_forward`. With `hostNetwork`
and a host that already has forwarding on, the privileged path is usually the
least fiddly. See [deploy/helm/tiredvpn/README.md](../deploy/helm/tiredvpn/README.md)
for the full `server.tun` value list.

## TLS Certificates

### Let's Encrypt (recommended for production)

```bash
# Install certbot
apt install certbot

# Get a certificate (stop any service on port 80 first)
certbot certonly --standalone -d your-server.com

# Certificates are at:
# /etc/letsencrypt/live/your-server.com/fullchain.pem
# /etc/letsencrypt/live/your-server.com/privkey.pem

tiredvpn server \
  -listen :443 \
  -cert /etc/letsencrypt/live/your-server.com/fullchain.pem \
  -key /etc/letsencrypt/live/your-server.com/privkey.pem \
  -secret <secret>
```

Auto-renew with a cron job:

```
0 0 1 * * certbot renew --quiet && systemctl reload tiredvpn
```

### Self-signed certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 3650 \
  -subj "/CN=your-server.com"
```

Self-signed works fine — TiredVPN does not validate the server certificate from the client side (authentication is via the shared secret). A real certificate is useful for the fake website camouflage.

## Systemd Service

```ini
# /etc/systemd/system/tiredvpn.service
[Unit]
Description=TiredVPN server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tiredvpn server \
  -listen :443 \
  -cert /etc/tiredvpn/server.crt \
  -key /etc/tiredvpn/server.key \
  -redis 127.0.0.1:6379 \
  -api-addr 127.0.0.1:8080 \
  -ip-pool 10.8.0.0/24 \
  -fake-root /var/www/tiredvpn
EnvironmentFile=/etc/tiredvpn/env
Restart=always
RestartSec=5
LimitNOFILE=65536

# Allow creating TUN interfaces
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/tiredvpn/env
# (do not commit this file)
TIREDVPN_SECRET=your-secret-here
```

If you pass the secret via an environment variable, adjust the `ExecStart` line to include `-secret ${TIREDVPN_SECRET}` and add the `EnvironmentFile` line.

```bash
systemctl daemon-reload
systemctl enable --now tiredvpn
journalctl -u tiredvpn -f
```

## Firewall

Allow inbound traffic on port 443 (both TCP and UDP):

```bash
# iptables
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT

# ufw
ufw allow 443/tcp
ufw allow 443/udp

# firewalld
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=443/udp
firewall-cmd --reload
```

If you use port hopping, also open the hop range:

```bash
iptables -A INPUT -p udp --dport 47000:47100 -j ACCEPT
```

For TUN mode on bare metal or a host install, enable IP forwarding and
masquerade by hand:

```bash
# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# NAT for VPN clients
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

In containers you do not run these by hand - the `tun` image entrypoint sets
forwarding and NAT itself. See [TUN mode in containers](#tun-mode-in-containers).

## Multi-Hop Setup

Chain two servers so traffic exits through a second node:

```
Client → Server A (relay, censor country) → Server B (exit, free country) → Internet
```

**Server B** (exit node, normal setup):

```bash
tiredvpn server \
  -listen :443 \
  -cert server-b.crt \
  -key server-b.key \
  -secret <upstream-secret>
```

**Server A** (relay, adds `-upstream`):

```bash
tiredvpn server \
  -listen :443 \
  -cert server-a.crt \
  -key server-a.key \
  -secret <client-secret> \
  -upstream server-b.example.com:443 \
  -upstream-secret <upstream-secret>
```

**Client** connects only to Server A:

```bash
tiredvpn client \
  -server server-a.example.com:443 \
  -secret <client-secret>
```

The client does not need to know about Server B.

## Scaling

For high-traffic deployments:

- Run multiple server instances behind a load balancer (use consistent hashing on client IP to keep sessions on the same instance)
- Use a central Redis cluster for shared client registry
- Expose the metrics endpoint and scrape with Prometheus + Grafana (see [monitoring.md](monitoring.md))
- Set `LimitNOFILE=65536` in the systemd unit (default Linux limit is too low for many concurrent connections)

```bash
# Check current file descriptor usage
cat /proc/$(pgrep tiredvpn)/fdinfo | wc -l
```

## IPv6 Deployment

Enable IPv6 on the server:

```bash
tiredvpn server \
  -listen :443 \
  -listen-v6 [::]:995 \
  -dual-stack \
  -cert server.crt \
  -key server.key \
  -secret <secret>
```

Clients will automatically prefer IPv6 when `-server-v6` is also set:

```bash
tiredvpn client \
  -server server.example.com:443 \
  -server-v6 [2001:db8::1]:995 \
  -prefer-ipv6 \
  -secret <secret>
```

Firewall (iptables for IPv6):

```bash
ip6tables -A INPUT -p tcp --dport 995 -j ACCEPT
ip6tables -A INPUT -p udp --dport 995 -j ACCEPT
```
