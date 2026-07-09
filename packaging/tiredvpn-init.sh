#!/usr/bin/env bash
#
# tiredvpn-init - finish setting up a TiredVPN server after the binary and unit
# are in place (via `apt install tiredvpn`, the rpm, or install.sh). It is
# idempotent: a secret and certificate are generated only if they don't already
# exist, so it is safe to re-run.
#
# What it does:
#   - generates a shared secret (if /etc/tiredvpn/env has none)
#   - generates a self-signed EC certificate (if missing)
#   - detects the server's public IP
#   - writes /etc/tiredvpn/env (mode 0600)
#   - enables and starts the systemd service
#   - prints the access keys: a tired:// connection string + QR, the secret,
#     and a ready-to-paste client command
#
# Flags:
#   --port N        listen port (default 443, or whatever is already in env)
#   --ip-pool CIDR  client IP pool for TUN/full-VPN mode (default 10.8.0.0/24);
#                   the service brings up ip_forward + NAT for it on start
#   --proxy-only    disable TUN mode (empty pool, SOCKS proxy only, no NAT)
#   --force         regenerate secret and certificate even if they exist
#   --no-start      configure but do not enable/start the service

set -euo pipefail

ETC_DIR="/etc/tiredvpn"
ENV_FILE="${ETC_DIR}/env"
ENV_EXAMPLE="${ETC_DIR}/env.example"
CERT="${ETC_DIR}/server.crt"
KEY="${ETC_DIR}/server.key"
BIN="$(command -v tiredvpn 2>/dev/null || echo /usr/bin/tiredvpn)"

PORT=""
FORCE=0
START=1
# IP pool resolution: default -> existing env -> --ip-pool -> --proxy-only.
# POOL_SET/PROXY_ONLY track explicit flags so they override the sourced env.
POOL_ARG=""
POOL_SET=0
PROXY_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --port=*) PORT="${1#*=}"; shift ;;
    --ip-pool) POOL_ARG="$2"; POOL_SET=1; shift 2 ;;
    --ip-pool=*) POOL_ARG="${1#*=}"; POOL_SET=1; shift ;;
    --proxy-only) PROXY_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    --no-start) START=0; shift ;;
    -h|--help)
      sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "tiredvpn-init: unknown argument: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "must run as root (try: sudo tiredvpn-init)"
  exit 1
fi

command -v openssl >/dev/null 2>&1 || { err "missing dependency: openssl"; exit 1; }

mkdir -p "$ETC_DIR"
chmod 0750 "$ETC_DIR"

# Seed env from the example on first run.
if [ ! -f "$ENV_FILE" ] && [ -f "$ENV_EXAMPLE" ]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
fi
touch "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# Read existing values (env file is shell-sourceable key=value).
# shellcheck disable=SC1090
. "$ENV_FILE" 2>/dev/null || true

# Resolve the listen port: explicit flag > existing env > default 443.
if [ -n "$PORT" ]; then
  LISTEN=":${PORT}"
elif [ -n "${TIREDVPN_LISTEN:-}" ]; then
  LISTEN="${TIREDVPN_LISTEN}"
  PORT="${LISTEN##*:}"
else
  LISTEN=":443"
  PORT="443"
fi

CERT="${TIREDVPN_CERT:-$CERT}"
KEY="${TIREDVPN_KEY:-$KEY}"

# Resolve the client IP pool for TUN mode.
#   default        -> 10.8.0.0/24 (TUN on by default; Android needs it)
#   existing env   -> keep whatever is already in the env file, if non-empty
#   --ip-pool CIDR -> override
#   --proxy-only   -> force empty (proxy-only, no NAT)
POOL="10.8.0.0/24"
if [ -n "${TIREDVPN_IP_POOL:-}" ]; then
  POOL="${TIREDVPN_IP_POOL}"
fi
if [ "$POOL_SET" -eq 1 ]; then
  POOL="$POOL_ARG"
fi
if [ "$PROXY_ONLY" -eq 1 ]; then
  POOL=""
fi

# Secret: keep existing unless --force.
SECRET="${TIREDVPN_SECRET:-}"
if [ -z "$SECRET" ] || [ "$FORCE" -eq 1 ]; then
  log "Generating shared secret"
  SECRET="$(openssl rand -hex 32)"
fi

# Certificate: keep existing unless --force.
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ] || [ "$FORCE" -eq 1 ]; then
  log "Generating self-signed certificate"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 3650 -nodes -keyout "$KEY" -out "$CERT" \
    -subj "/CN=tiredvpn" >/dev/null 2>&1
  chmod 0600 "$KEY"
  chmod 0644 "$CERT"
fi

# Public IP detection: best-effort, fall back to a placeholder.
detect_public_ip() {
  local ip=""
  for url in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
    ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')" || ip=""
    case "$ip" in
      *[0-9].[0-9]*) printf '%s' "$ip"; return 0 ;;
    esac
  done
  ip="$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}')" || ip=""
  [ -n "$ip" ] && { printf '%s' "$ip"; return 0; }
  printf 'YOUR_SERVER_IP'
}
log "Detecting public IP"
PUBLIC_IP="$(detect_public_ip)"

# Write env (0600).
log "Writing ${ENV_FILE}"
cat > "$ENV_FILE" <<EOF
# Managed by tiredvpn-init. See ${ENV_EXAMPLE} for documentation.
TIREDVPN_LISTEN=${LISTEN}
TIREDVPN_CERT=${CERT}
TIREDVPN_KEY=${KEY}
TIREDVPN_SECRET=${SECRET}
TIREDVPN_IP_POOL=${POOL}
EOF
chmod 0600 "$ENV_FILE"

if [ "$START" -eq 1 ]; then
  log "Enabling and starting tiredvpn"
  systemctl daemon-reload || true
  systemctl enable --now tiredvpn || err "could not start service (check: journalctl -u tiredvpn)"
else
  systemctl daemon-reload || true
fi

# Print the access keys.
echo
echo "============================================================"
echo " TiredVPN server is configured."
echo "============================================================"
echo "  Server:  ${PUBLIC_IP}:${PORT}"
echo "  Secret:  ${SECRET}"
echo
echo "  Client (SOCKS5 proxy on 127.0.0.1:1080):"
echo "    tiredvpn client -server ${PUBLIC_IP}:${PORT} -secret ${SECRET} -listen 127.0.0.1:1080"
echo
echo "  Connection string and QR (for the mobile app):"
echo "------------------------------------------------------------"
if [ -x "$BIN" ]; then
  "$BIN" admin qr -server "${PUBLIC_IP}:${PORT}" -secret "${SECRET}" || true
fi
echo "------------------------------------------------------------"
if [ "$PUBLIC_IP" = "YOUR_SERVER_IP" ]; then
  echo "  NOTE: public IP could not be detected - replace YOUR_SERVER_IP above."
fi
if [ -n "$POOL" ]; then
  echo "  TUN/full-VPN mode ON (pool ${POOL}); ip_forward + NAT are configured"
  echo "  automatically by the service on start."
else
  echo "  Proxy-only mode (no IP pool): SOCKS proxy only, no TUN/NAT."
fi
echo "  See: https://github.com/tiredvpn/tiredvpn#server-firewall-and-forwarding-required-for-tun-mode"
echo
