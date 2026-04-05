# Security Model

This document describes TiredVPN's security mechanisms and operational security recommendations.

## Authentication

### Secret generation

Secrets must be cryptographically random. Generate them with:

```bash
openssl rand -hex 32
# 64 hex characters = 32 bytes = 256 bits of entropy
```

### HMAC-SHA256 authentication

Every connection is authenticated with an HMAC-SHA256 token:

```
token = HMAC-SHA256(secret, timestamp_bucket || context)
timestamp_bucket = unix_timestamp / 300   # 5-minute window
```

Properties:
- **Replay protection**: tokens are only valid within a ±1 bucket window (~10 minutes total). Captured tokens cannot be replayed later.
- **Per-connection binding**: the `context` field binds the token to connection-specific data, preventing cross-connection reuse.
- **No PKI required**: authentication does not depend on certificate chains. The shared secret is the sole credential.

### Multi-client mode

In Redis-backed multi-client mode:
- Each client has a unique secret stored in Redis
- Secrets are looked up by prefix to identify the client record
- Clients can be individually revoked (deleted from Redis) with immediate effect
- Optional per-client expiry (`expires_at` field in client config)

### Protecting secrets

- Store secrets in environment variables or a secrets manager, not in shell history or config files
- Use a unique secret per client in multi-client mode
- Rotate secrets periodically; the old secret becomes invalid immediately
- The server secret is never transmitted in plaintext — only the HMAC token is sent

## Transport Security

### TLS with uTLS fingerprinting

All TCP connections use TLS 1.3. The [uTLS](https://github.com/refraction-networking/utls) library is used to mimic real browser TLS fingerprints (Chrome, Firefox, iOS Safari) so the TLS handshake is indistinguishable from a legitimate browser connection.

The server certificate is only used for the TLS handshake camouflage. Authentication uses the HMAC secret, not the certificate.

### QUIC

QUIC connections use TLS 1.3 internally (as per RFC 9001). QUIC version draft-29 spoofing is optionally used to avoid version fingerprinting.

### Kernel TLS offload (kTLS)

On Linux kernels that support it, TLS encryption/decryption is offloaded to the kernel (`AF_KTLSt`). This reduces CPU overhead and improves throughput. TiredVPN detects kTLS support at startup:

```
INF kTLS: kernel TLS support detected, will offload encryption
```

kTLS is used automatically when available; no configuration is needed.

## REALITY Protocol

REALITY is a TLS extension that authenticates the client without modifying the visible TLS handshake. The protocol:

1. Client sends a standard TLS ClientHello with a custom extension containing an X25519 public key and HMAC auth token
2. Server verifies the HMAC token; if invalid, it proxies the connection to a real website (the "reality" of the name)
3. If valid, server responds with its X25519 public key; both sides derive a shared session key
4. Post-quantum upgrade: if `-pq` is enabled, ML-KEM-768 key encapsulation is layered on top of X25519

To a network observer or DPI probe, the server looks like an ordinary HTTPS site responding to a browser.

## Encrypted Client Hello (ECH)

ECH hides the actual server name (SNI) from network observers:

```
Without ECH:  ClientHello → SNI: your-server.com  (visible to ISP/DPI)
With ECH:     ClientHello → SNI: cloudflare-ech.com (outer, visible)
                         → Encrypted inner: SNI: your-server.com
```

The outer SNI (`-ech-public-name`, default `cloudflare-ech.com`) is what the network sees. The real server name is encrypted and visible only to the server.

Enable with:

```bash
tiredvpn client -server host:443 -secret <s> -ech
```

## Post-Quantum Cryptography

When `-pq` is enabled:

- **ML-KEM-768** (NIST FIPS 203): post-quantum key encapsulation, replacing classical ECDH for key exchange
- **ML-DSA-65** (NIST FIPS 204): post-quantum digital signatures, used to sign the handshake

These algorithms are quantum-resistant, protecting against harvest-now-decrypt-later attacks where an adversary records encrypted traffic today to decrypt it once a quantum computer is available.

```bash
tiredvpn client \
  -server host:443 \
  -secret <secret> \
  -pq \
  -pq-server-key <base64-ml-kem-pubkey>
```

The server's ML-KEM public key should be obtained out-of-band and verified before use.

## Traffic Analysis Resistance

### Salamander padding

Salamander pads QUIC Initial packets to a uniform size, removing packet-length fingerprints. Three levels are available (Conservative / Balanced / Aggressive). Enabled automatically when using `quic_salamander` strategy.

### RTT masking

The `-rtt-masking` flag adds artificial latency jitter matching the chosen profile (`-rtt-profile`). This defeats timing-based VPN detection that measures round-trip times to identify proxy hops.

### Traffic morphing

`morph_*` strategies reshape the traffic byte-distribution and inter-packet timing to match video streaming profiles (Yandex Video, VK Video). Effective against statistical classifiers.

## Operational Security

### Server hardening

```bash
# Run as a dedicated user (no root after startup)
useradd -r -s /bin/false tiredvpn
# Requires capabilities for TUN and raw sockets
setcap 'cap_net_admin,cap_net_raw+ep' /usr/local/bin/tiredvpn

# Restrict API access to localhost
tiredvpn server -api-addr 127.0.0.1:8080 ...
# Never: -api-addr 0.0.0.0:8080
```

### Network exposure

- Only ports 443/tcp and 443/udp (or your chosen port range) should be publicly accessible
- The `-api-addr` endpoint must never be exposed publicly — it provides unauthenticated access to client management
- The `-pprof` endpoint must never be exposed publicly — it exposes memory contents

### Certificate management

- Use real certificates from a trusted CA to make the fake website convincing
- Automate renewal (Let's Encrypt via certbot) to avoid expiry
- Store private keys with `600` permissions, owned by the tiredvpn user

### Secret rotation

To rotate a shared secret with zero downtime:

1. Start a second server instance on a different port with the new secret
2. Update clients to the new secret
3. Stop the old server instance

In multi-client mode with Redis, simply delete the old client entry and create a new one. Active sessions will be terminated.

## Vulnerability Reporting

If you discover a security vulnerability, please report it privately as described in [SECURITY.md](../SECURITY.md). Do not open a public issue.
