# Admin & Client Management

`tiredvpn admin` manages clients when the server runs in multi-client mode (with Redis).

## Prerequisites

The server must be started with `-redis` and `-api-addr`:

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080
```

## Commands

### Add a client

```bash
tiredvpn admin add \
  -api http://127.0.0.1:8080 \
  -server vpn.example.com:443
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `-api` | | **[required]** Server API address |
| `-server` | | **[required]** Server address used in the connection string |
| `-id` | auto-generated | Client ID (UUID) |
| `-secret` | auto-generated | Client secret (hex string) |
| `-quic` | `true` | Include QUIC in the generated connection string |
| `-quic-port` | `443` | QUIC port in the connection string |

The command prints the new client's ID, secret, and a ready-to-use connection string.

Example output:

```
Client added:
  ID:     7f4e3a21-b8c2-4d19-a5f1-0e8c3d7b1920
  Secret: a3f1c9e2b7d05481f6e3a2c8d9b04572
  Connect:
    tiredvpn client -server vpn.example.com:443 -secret a3f1c9e2b7d05481f6e3a2c8d9b04572
```

### List clients

```bash
tiredvpn admin list -api http://127.0.0.1:8080
```

Lists all registered clients with ID, creation date, and connection count.

### Delete a client

```bash
tiredvpn admin delete \
  -api http://127.0.0.1:8080 \
  -id 7f4e3a21-b8c2-4d19-a5f1-0e8c3d7b1920
```

Immediately revokes the client's secret. Active sessions using that secret will be terminated.

### Generate a QR code

Generates a QR code encoding the connection string. Useful for provisioning mobile clients.

```bash
tiredvpn admin qr \
  -server vpn.example.com:443 \
  -secret <secret>
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | | **[required]** Server address |
| `-secret` | | **[required]** Client secret |
| `-quic` | `true` | Enable QUIC in connection string |
| `-quic-port` | `443` | QUIC port |
| `-strategy` | `auto` | Override strategy in connection string |
| `-cover` | `api.googleapis.com` | Cover host |

The QR code is printed as ASCII art to stdout. Scan it with the TiredVPN mobile app to configure the client automatically.

## REST API

The management API is available at the address specified by `-api-addr`. By default it binds to `127.0.0.1:8080` (localhost only).

### Client endpoints

#### List clients

```
GET /clients
```

Response:

```json
[
  {
    "id": "7f4e3a21-b8c2-4d19-a5f1-0e8c3d7b1920",
    "name": "",
    "secret": "a3f1c9e2...",
    "tun_ip": "10.8.0.2",
    "enabled": true,
    "created_at": "2025-01-15T10:00:00Z",
    "expires_at": null
  }
]
```

#### Create client

```
POST /clients
Content-Type: application/json

{
  "id": "optional-custom-id",
  "secret": "optional-custom-secret",
  "name": "optional-label",
  "max_conns": 10,
  "max_bandwidth": 10485760
}
```

Response includes the new client's full config.

#### Get client

```
GET /clients/{id}
```

#### Update client

```
PUT /clients/{id}
Content-Type: application/json

{
  "enabled": false
}
```

#### Delete client

```
DELETE /clients/{id}
```

### Other endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/metrics` | Prometheus metrics (text/plain) |
| `GET` | `/health` | Server health (`{"status":"ok"}`) |

## Securing the API

By default the API binds to `127.0.0.1` and is not reachable from the network. If you need remote access, use an SSH tunnel or a reverse proxy with authentication — do not expose the API publicly.

```bash
# Access remote API via SSH tunnel
ssh -L 8080:127.0.0.1:8080 user@your-server.com

# Then use locally:
tiredvpn admin list -api http://127.0.0.1:8080
```

## Client data model

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID identifier |
| `name` | string | Optional display label |
| `secret` | string | HMAC secret (hex) |
| `tun_ip` | string | Assigned VPN IP (from `-ip-pool`) |
| `max_conns` | int | Max simultaneous connections (0 = unlimited) |
| `max_bandwidth` | int64 | Bandwidth limit in bytes/sec (0 = unlimited) |
| `enabled` | bool | Whether this client can connect |
| `created_at` | time | Creation timestamp |
| `expires_at` | time | Expiry timestamp (zero = never expires) |
