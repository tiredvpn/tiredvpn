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
    cap_add:
      - NET_ADMIN   # required for TUN mode
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=0

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

### Build the image locally

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
docker build -t tiredvpn:local .
```

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

For TUN mode, enable IP forwarding and masquerade:

```bash
# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# NAT for VPN clients
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

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
