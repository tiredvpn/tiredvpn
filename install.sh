#!/usr/bin/env bash
#
# TiredVPN server installer. One command sets up a server and prints the access
# keys:
#
#   curl -fsSL https://tiredvpn.github.io/tiredvpn/install.sh | sudo bash -s -- --port 443
#
# By default it adds the apt/yum repository and installs the native package; on
# systems without apt/dnf it falls back to downloading the release binary. Then
# it runs tiredvpn-init, which generates a secret and certificate, starts the
# service, and prints a tired:// connection string + QR.
#
# Flags:
#   --port N            listen port (default 443)
#   --method repo|binary  force install method (default: repo if apt/dnf exists)
#   --proxy-only        SOCKS proxy only, disable TUN/full-VPN mode (no NAT)
#   --force             regenerate secret/certificate even if they exist
#
# TUN/full-VPN mode is on by default (the Android app needs it); the service
# brings up ip_forward + NAT for the client pool automatically. Use --proxy-only
# for a SOCKS-proxy-only server.
set -euo pipefail

REPO="tiredvpn/tiredvpn"
PAGES_URL="https://tiredvpn.github.io/tiredvpn"
RAW_URL="https://raw.githubusercontent.com/${REPO}/main"
REL_URL="https://github.com/${REPO}/releases/latest/download"
KEYRING="/usr/share/keyrings/tiredvpn-archive-keyring.gpg"

PORT=443
METHOD=""
FORCE=0
PROXY_ONLY=0

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --port=*) PORT="${1#*=}"; shift ;;
    --method) METHOD="$2"; shift 2 ;;
    --method=*) METHOD="${1#*=}"; shift ;;
    --proxy-only) PROXY_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (pipe into: sudo bash)"

case "$(uname -s)" in
  Linux) : ;;
  *) die "this installer supports Linux only" ;;
esac

case "$(uname -m)" in
  x86_64|amd64)   ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

for dep in curl openssl; do
  command -v "$dep" >/dev/null 2>&1 || die "missing dependency: $dep"
done
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"

# Pick the install method.
if [ -z "$METHOD" ]; then
  if command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    METHOD="repo"
  else
    METHOD="binary"
  fi
fi

install_via_apt() {
  log "Adding TiredVPN apt repository"
  install -d -m 0755 "$(dirname "$KEYRING")"
  curl -fsSL "${PAGES_URL}/gpg.key" | gpg --dearmor -o "$KEYRING"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=${KEYRING}] ${PAGES_URL}/apt stable main" \
    > /etc/apt/sources.list.d/tiredvpn.list
  apt-get update -y
  apt-get install -y tiredvpn
}

install_via_dnf() {
  log "Adding TiredVPN yum repository"
  cat > /etc/yum.repos.d/tiredvpn.repo <<EOF
[tiredvpn]
name=TiredVPN
baseurl=${PAGES_URL}/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=${PAGES_URL}/gpg.key
EOF
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y tiredvpn
  else
    yum install -y tiredvpn
  fi
}

install_via_binary() {
  log "Downloading TiredVPN ${ARCH} binary"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "${REL_URL}/tiredvpn-linux-${ARCH}.tar.gz" -o "${tmp}/t.tar.gz"
  curl -fsSL "${REL_URL}/checksums.txt" -o "${tmp}/checksums.txt"
  ( cd "$tmp" && grep "tiredvpn-linux-${ARCH}.tar.gz" checksums.txt | sha256sum -c - ) \
    || die "checksum verification failed"
  tar -xzf "${tmp}/t.tar.gz" -C "$tmp"
  install -m 0755 "${tmp}/tiredvpn-linux-${ARCH}" /usr/bin/tiredvpn

  log "Installing service unit and init helper"
  curl -fsSL "${RAW_URL}/packaging/tiredvpn-init.sh" -o /usr/bin/tiredvpn-init
  chmod 0755 /usr/bin/tiredvpn-init
  curl -fsSL "${RAW_URL}/packaging/tiredvpn-nat.sh" -o /usr/bin/tiredvpn-nat
  chmod 0755 /usr/bin/tiredvpn-nat
  install -d -m 0750 /etc/tiredvpn
  curl -fsSL "${RAW_URL}/packaging/tiredvpn.service" -o /lib/systemd/system/tiredvpn.service
  curl -fsSL "${RAW_URL}/packaging/tiredvpn.env.example" -o /etc/tiredvpn/env.example
  systemctl daemon-reload
}

case "$METHOD" in
  repo)
    if command -v apt-get >/dev/null 2>&1; then
      install_via_apt
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
      install_via_dnf
    else
      die "no apt/dnf/yum found; retry with --method binary"
    fi
    ;;
  binary) install_via_binary ;;
  *) die "unknown method: $METHOD" ;;
esac

# Finish: generate keys, start, print connection info.
init_args="--port ${PORT}"
[ "$FORCE" -eq 1 ] && init_args="${init_args} --force"
[ "$PROXY_ONLY" -eq 1 ] && init_args="${init_args} --proxy-only"
log "Configuring server"
# shellcheck disable=SC2086
tiredvpn-init ${init_args}
