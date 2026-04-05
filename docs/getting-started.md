# Getting Started

This guide walks you through deploying a TiredVPN server and connecting your first client.

## Prerequisites

- A Linux server with a public IP address
- Go 1.26+ (for building from source), or use the pre-built binary / Docker image
- Port 443 open for both TCP and UDP traffic
- A TLS certificate (self-signed is fine; the server fakes a website for unauthenticated visitors)

## 1. Get TiredVPN

### Pre-built binary

Download the latest release from the [releases page](https://github.com/tiredvpn/tiredvpn/releases).

### Build from source

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
make build
# binary: ./tiredvpn
```

### Docker

```bash
docker pull tiredvpn/tiredvpn:latest
```

## 2. Generate a shared secret

```bash
openssl rand -hex 32
# example output: a3f1c9e2b7d05481f6e3a2c8d9b04572e1f8c3a6d7e2b5f9081c4d3e6a7b8c90
```

Keep this secret; you will use it on both the server and client.

## 3. Generate a TLS certificate

If you do not have a real certificate, generate a self-signed one:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 3650 \
  -subj "/CN=your-server.com"
```

For production use Let's Encrypt or any CA-signed certificate. See [deployment.md](deployment.md) for details.

## 4. Start the server

```bash
./tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <your-secret>
```

The server now:
- Accepts TLS (TCP) on `:443`
- Accepts QUIC (UDP) on `:443`
- Serves a fake website to unauthenticated visitors (DPI camouflage)
- Authenticates clients by HMAC-verified secret

To verify the server is running:

```bash
curl -sk https://localhost:443/
# returns the fake website content
```

## 5. Connect a client (SOCKS5 proxy mode)

On your client machine:

```bash
./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -listen 127.0.0.1:1080
```

This starts a local SOCKS5 proxy on `127.0.0.1:1080`. Point any application to it:

```bash
# Test with curl
curl --socks5 127.0.0.1:1080 https://api.ipify.org
# Should return the server's IP address

# Firefox: Settings → Network → Manual proxy → SOCKS5: 127.0.0.1:1080
```

The client automatically probes all available strategies and selects the best one. If a strategy gets blocked mid-session, it falls back to another without dropping connections.

## 6. Connect a client (full VPN / TUN mode)

TUN mode routes all system traffic through the VPN. Requires `root` or `CAP_NET_ADMIN`.

```bash
sudo ./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -tun \
  -tun-routes 0.0.0.0/0
```

This creates a `tiredvpn0` TUN interface and adds a default route through it.

To route only specific subnets (split tunnel):

```bash
sudo ./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -tun \
  -tun-routes 10.0.0.0/8,192.168.100.0/24
```

## 7. Enable QUIC for better performance

QUIC (UDP-based) is faster and harder to block than TLS over TCP:

```bash
./tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -quic \
  -listen 127.0.0.1:1080
```

## Next steps

- [Server configuration reference](server.md) — all server flags
- [Client configuration reference](client.md) — all client flags, evasion options
- [DPI bypass strategies](strategies.md) — how the adaptive engine works
- [Production deployment](deployment.md) — Docker, systemd, multi-hop
- [Security model](security.md) — auth, ECH, post-quantum crypto
