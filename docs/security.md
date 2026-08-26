# Security Model

This document describes what TiredVPN's cryptography actually does, what it does
not do, and how to run a server without making the situation worse. Where a
mechanism is weaker than its name suggests, that is said here rather than left
for the reader to find in the source.

## Scope

TiredVPN is built to get traffic past a censor. That is a different goal from
protecting traffic against one, and the two do not always point the same way —
the section on post-quantum key exchange below is an example where evading
detection won and a security property was given up on purpose.

Concretely, the design assumes an adversary who inspects, classifies, throttles
and blocks traffic, and who can probe your server. It does not assume an
adversary who has your shared secret, and several of the transports below do not
survive an adversary who can terminate TLS in the path. If your threat model
includes an active man-in-the-middle rather than a censor, read the
per-transport section carefully before relying on this.

## Authentication

### Secret generation

The secret is the only credential. Generate it from a CSPRNG:

```bash
openssl rand -hex 32      # 32 bytes, 256 bits
```

The server refuses to start in single-secret mode without `-secret` or
`TIREDVPN_SECRET`. The **client** does not: with no secret it logs
`No secret provided - using default (INSECURE!)` and uses a hardcoded string.
Treat that warning as a failure.

### The two token schemes

**REALITY (legacy path).** The client generates a fresh X25519 key pair per
connection and sends `[pubkey:32][token:32]` inside a TLS padding extension,
where

```
token = HMAC-SHA256(secret, clientPubKey || unix_time/300)
```

The server accepts the current 5-minute bucket and one on either side. Because
the token covers a key that is new for every connection, capturing one buys
nothing: it cannot be replayed onto a different connection.

**Everything else** — HTTP/2 stego, morph, WebSocket-padded, HTTP polling,
anti-probe — sends

```
token = HMAC-SHA256(secret, unix_time/60 || "http2-stego-auth")
```

and the server accepts ±10 minutes of skew. Note what this token does *not*
cover: it is not bound to the connection, the key exchange, or anything else.
Anyone who observes one has a working credential for roughly the next twenty
minutes and can use the server as a proxy for that long. The wide window is
deliberate — production logs showed clients failing on clock drift with a
±1-minute window — but the replay exposure is real and is the price.

**REALITY B1** authenticates differently again; see below.

### Multi-client mode

With `-redis`, each client has its own secret and the server tries the presented
token against every registered secret in turn. Deleting a client from Redis
revokes it at once, and `expires_at` gives per-client expiry. Without Redis
there is a single global secret shared by every client — which also means one
client's traffic is not cryptographically separated from another's.

### Protecting secrets

- Keep secrets in environment variables or a secrets manager, not in shell
  history or world-readable config files.
- Use a distinct secret per client whenever Redis is available.
- The secret itself is never sent; only tokens derived from it.

## Transport security, transport by transport

TiredVPN has several transports with genuinely different security properties.
The differences matter and are not interchangeable.

### REALITY, legacy path (`-reality-legacy`, on by default)

This is the transport most deployments use, and the name is misleading. It is
not the XTLS REALITY protocol, and after the first round trip it is not TLS at
all.

What happens: the client sends a uTLS-generated ClientHello with its credentials
in the padding extension. The server dials the donor named in the SNI, forwards
the ClientHello, reads back the donor's genuine ServerHello, injects its own
extension into it, sends it to the client — and closes the connection to the
donor. There is no Certificate message, no Finished, no TLS key schedule. The
handshake exists to look right on the wire, and it stops there.

Everything after that is our own record layer, framed to look like TLS
application data. There are two versions of it:

| | data layer v1 | data layer v2 |
|---|---|---|
| Cipher | ChaCha20 keystream, no MAC | ChaCha20-Poly1305 |
| Key from | `HKDF(secret, salt=clientPubKey)` | X25519 ECDH ‖ secret, both salts, both public keys |
| Integrity | none | per-record AEAD tag, TLS-style nonce, sticky failure |
| Forward secrecy | no | yes |

v2 is negotiated: the client appends `[salt][MAC]` after its credentials and the
server confirms with its own `[salt][MAC]` covering both public keys and both
salts, which is also what stops an active middlebox substituting its own key
share. If the confirmation is missing, **the connection silently falls back to
v1** unless `-reality-require-data-v2` is set on both ends. Turn that on once
your fleet is fully upgraded; until then, assume some connections are running
v1, with no integrity protection and no forward secrecy.

One earlier defect is fixed and worth stating because it changes what old
captures mean: the client's X25519 key used to be generated once per process, so
every connection that process made reused one ChaCha20 keystream from counter
zero. The key is now generated per connection, which also makes the v1 key
per-connection.

Server authentication on this path is the ack token,
`HMAC-SHA256(secret, clientPubKey || "reality-server-ack")`, in the ServerHello
padding. The client verifies it before proceeding, so a middlebox without the
secret cannot impersonate the server — and because it covers a fresh client key,
it cannot be replayed either.

### REALITY B1 (`-reality-b1`, off by default)

B1 is what the legacy path is not: a real TLS 1.3 handshake, end to end,
completed by uTLS on the client and `crypto/tls` on the server.

- **Client to server.** Authentication is sealed into the 32 bytes of
  `legacy_session_id`, keyed from the client's ephemeral X25519 key share and the
  server's static public key, with the marshalled ClientHello as associated data.
  After the handshake the client sends an exporter binding: an HMAC over RFC 8446
  §7.5 keying material, which a MITM that terminates TLS cannot produce because
  it sees different keying material on each side.
- **Server to client.** The certificate is self-signed and nobody builds a chain
  for it, so the signature field carries an HMAC keyed with the connection's auth
  key instead. The client checks it inside `VerifyPeerCertificate`, during the
  handshake, so a server that cannot prove itself never receives application
  data.

Enabling B1 needs `-reality-private-key` on the server (generate with
`tiredvpn reality-keygen`) and the matching `-reality-server-pubkey` on the
client. There is no probing and no downgrade: a client configured for B1 speaks
B1.

### The ordinary TLS transports

HTTP/2 stego, morph, WebSocket-padded, HTTP polling and anti-probe run over a
genuine TLS 1.3 connection to our server. Two caveats:

- Every strategy dials with `InsecureSkipVerify: true`. The certificate is
  camouflage for the cover domain, not an identity, and only B1 replaces the
  check with something else. Nothing else in the client verifies who it is
  talking to.
- The server proves nothing useful in return. The stego ack is
  `HMAC(secret, "server-ack")` — a fixed value with no per-connection input, so
  it is replayable by anyone who has ever seen one. Morph gets a single `0x00`
  byte; WebSocket-padded gets an HTTP 101.

So on these transports, an adversary who can terminate TLS in the path and who
has captured one auth token within the last twenty minutes can sit in the
middle. That is the combined effect of the replayable token, the disabled
certificate check and the absent server proof. If that is in your threat model,
use B1.

### QUIC and Salamander

QUIC connections carry their own TLS 1.3 (RFC 9001); that is where the
confidentiality of a QUIC session comes from.

Salamander is the outer obfuscation layer wrapping every UDP datagram:
`[salt:8][data XOR BLAKE2b-256(secret‖salt)][random padding]`, padded to size
buckets. It is not an AEAD. The only check that a datagram came from someone
holding the secret is a **2-byte tag**, so a datagram encrypted under a different
secret is accepted with probability 1/65536. That is an acceptance and
resource-exhaustion concern, not a confidentiality one — QUIC's own crypto
rejects whatever gets through — but it is a genuine protocol weakness rather than
a test artefact.

Salamander is applied to the whole datagram stream at the `Balanced` level, not
only to QUIC Initial packets.

### Kernel TLS

On Linux kernels with `SOL_TLS`, the server hands the socket to the kernel after
the authentication phase completes, so bulk relaying is encrypted in kernel
space (`internal/ktls`). This is a throughput optimisation; the cipher and keys
are the ones TLS negotiated, and nothing about the security properties changes.
It is not available on other platforms.

## Encrypted Client Hello

ECH is implemented but narrower than it looks.

- It applies to the **stego** and **anti-probe** strategies only. REALITY does
  not use it; its SNI hiding comes from the donor name and from splitting the
  ClientHello mid-hostname.
- It needs an `ECHConfigList` supplied out of band via `-ech-config`. Discovery
  from DNS HTTPS records is a stub that returns nothing, and server-side config
  generation is not implemented.
- With no config list, `-ech` alone changes nothing.
- On rejection the default is to retry with the server-supplied retry config and
  then fall back to plain TLS, so a failure is silent by design.

```bash
tiredvpn client -server host:443 -secret <s> -ech -ech-config <base64>
```

`-ech-public-name` (default `cloudflare-ech.com`) is the outer SNI a network
observer sees.

## Post-quantum cryptography

Read this section before relying on `-pq`.

**`-pq` and `-pq-server-key` do not affect the connection.** They construct
ML-KEM-768 and ML-DSA-65 key material and store it on the strategy, and nothing
in the handshake or data path reads it. The observable effects are a log line and
a different string in the strategy description. Treat these flags as unfinished
work, not as protection against harvest-now-decrypt-later.

What *is* real is the TLS key exchange group, and there the choice went the other
way on purpose. The server's shared TLS listener offers X25519, P-256 and P-384,
and **drops the X25519MLKEM768 hybrid by default**. The reason is recorded in
`internal/server/tlsprofile.go`: with the hybrid enabled our ServerHello was
1221 bytes of plaintext where eleven of thirteen donor sites send 133, and 1088
of those bytes are an ML-KEM key in the clear. A connection claiming
`SNI=yandex.ru` and answering with a post-quantum key is identifiable on the
first response packet, with no statistics and no active probe.

The exception is per donor: the two donor names that genuinely negotiate ML-KEM
get the hybrid list, because under those names it is the unremarkable answer.

The cost is stated plainly in that file and is repeated here: for stego, morph,
WebSocket-padded, HTTP polling and anti-probe the outer TLS is the only
confidentiality layer, so those transports have no hedge against
record-now-decrypt-later. B1 is less exposed — the client's X25519 in
`session_id` and the AEAD channel underneath both stand on their own — but it is
not post-quantum either.

## Traffic analysis resistance

These mechanisms target classifiers, not decryption.

- **Salamander padding** normalises UDP datagram sizes into buckets
  (Conservative / Balanced / Aggressive).
- **RTT masking** (`-rtt-masking`, `-rtt-profile`) shapes round-trip timing
  against detectors that fingerprint proxy hops by latency.
- **Traffic morphing** (`morph_*`) reshapes byte-size distribution and
  inter-packet timing towards measured video-streaming profiles.
- **Handshake gating** serialises TLS handshakes per donor SNI, so the client
  does not manufacture the burst pattern that per-SNI throttling looks for.
- **Fingerprint stability.** The uTLS profile is fixed for the lifetime of a
  strategy and never rotated per connection: switching profiles mid-session is
  itself a signal, and doing it after a censor has throttled a name escalates a
  120-second freeze into a 600-second block of all TLS.

## Operational hardening

### The management API

```bash
tiredvpn server -api-addr 127.0.0.1:8080 -api-token "$(openssl rand -hex 32)" ...
```

`-api-addr` defaults to `127.0.0.1:8080`. `-api-token` defaults to **empty,
which disables authentication entirely** — the API then grants unauthenticated
client management to anyone who can reach the port. Set a token, keep the
listener on loopback, and put it behind a reverse proxy or an SSH tunnel if it
must be reachable at all.

`-pprof` exposes process memory. Never bind it publicly.

### Privileges

```bash
useradd -r -s /bin/false tiredvpn
setcap 'cap_net_admin,cap_net_raw+ep' /usr/local/bin/tiredvpn
```

TUN and raw sockets need `CAP_NET_ADMIN` and `CAP_NET_RAW`; the binary probes
for both at startup (`internal/capabilities`) and reports what is missing rather
than failing obscurely later.

### Network exposure

- Publish only the transport ports (typically 443/tcp and 443/udp, plus any
  hopping range).
- The unauthenticated-probe answer is worth configuring:
  `-reality-cover-domain` forwards probes that fail REALITY authentication to a
  real site. With it empty the connection falls through to the ordinary TLS path
  and gets the fake website, which is the same answer every other unrecognised
  connection gets.
- `-node-max-clients` and `-node-max-bytes` cap what one node carries. Address
  reputation is the one blocking vector that ignores traffic shape, and these
  ceilings are enforced after authentication so a probe cannot measure them.

### Certificates

- Use a certificate from a real CA so the fake website is convincing, and
  automate renewal.
- Store keys `600`, owned by the service user.
- Remember that on every transport except B1 the client does not verify the
  certificate. It is camouflage, not identity.

### Secret rotation

Zero-downtime rotation with a global secret:

1. Start a second instance on another port with the new secret.
2. Move clients over.
3. Stop the old instance.

In multi-client mode, delete the Redis entry and create a new one; live sessions
for that client are terminated.

## Known limitations

Collected here so they are not spread across the document:

1. The default REALITY path is not TLS after the ServerHello, and can fall back
   to an unauthenticated ChaCha20 record layer with no forward secrecy unless
   `-reality-require-data-v2` is set on both ends.
2. `-pq` and `-pq-server-key` are inert. No post-quantum key exchange happens on
   any path as a result of setting them.
3. Post-quantum TLS groups are deliberately disabled on the shared listener, so
   the non-REALITY transports have no record-now-decrypt-later hedge.
4. Auth tokens on the non-REALITY transports are replayable for about twenty
   minutes and are not bound to the connection.
5. No transport except B1 authenticates the server to the client in a way that
   survives an active MITM; certificate verification is off everywhere.
6. ECH covers two strategies, needs an out-of-band config list, and falls back
   to plain TLS silently.
7. Salamander's secret check is 2 bytes wide.
8. Without Redis, all clients share one secret.

## Vulnerability reporting

Report privately as described in [SECURITY.md](../SECURITY.md). Do not open a
public issue.
