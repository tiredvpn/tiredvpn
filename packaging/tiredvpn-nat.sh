#!/bin/sh
# tiredvpn-nat - bare-metal NAT helper for TiredVPN server TUN mode.
#
# Mirrors the NAT setup in docker/entrypoint.sh, but for a systemd host. It is
# meant to run as `ExecStartPre=-/usr/bin/tiredvpn-nat` so the service brings up
# ip_forward + MASQUERADE for the client IP pool on its own.
#
# The pool comes from the first argument ($1) or the TIREDVPN_IP_POOL env var
# (systemd exposes the EnvironmentFile to ExecStartPre). An empty pool means
# proxy mode: nothing to do.
#
# Env overrides:
#   TIREDVPN_IP_POOL    - client CIDR pool (if $1 is not given).
#   TIREDVPN_WAN_IFACE  - force WAN interface instead of autodetecting it.
#
# Every failure is a warning, never fatal: the script always exits 0 so a
# missing capability or tool never blocks the unit from starting.

set -u

log() {
    echo "[tiredvpn-nat] $*" >&2
}

POOL="${1:-${TIREDVPN_IP_POOL:-}}"

if [ -z "$POOL" ]; then
    log "proxy mode (no ip pool), skipping NAT setup"
    exit 0
fi

log "server TUN mode ($POOL), configuring NAT"

# Enable IPv4 forwarding. Warn but continue on failure.
if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    log "WARN: could not set net.ipv4.ip_forward=1"
fi

# Determine WAN interface: env override, else route to a public IP.
WAN="${TIREDVPN_WAN_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}')}"

if [ -z "$WAN" ]; then
    log "WARN: could not determine WAN interface (set TIREDVPN_WAN_IFACE) - skipping NAT setup"
    exit 0
fi

log "using WAN interface: $WAN"

# Idempotent rule install: check (-C) before append (-A).
if iptables -t nat -C POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null; then
    log "nat POSTROUTING masquerade rule already present"
elif iptables -t nat -A POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null; then
    log "added nat POSTROUTING MASQUERADE -s $POOL -o $WAN"
else
    log "WARN: failed to add MASQUERADE rule - host likely lacks NET_ADMIN"
fi

if iptables -C FORWARD -s "$POOL" -j ACCEPT 2>/dev/null; then
    log "forward (src) rule already present"
elif iptables -A FORWARD -s "$POOL" -j ACCEPT 2>/dev/null; then
    log "added FORWARD ACCEPT -s $POOL"
else
    log "WARN: failed to add FORWARD (src) rule - host likely lacks NET_ADMIN"
fi

if iptables -C FORWARD -d "$POOL" -j ACCEPT 2>/dev/null; then
    log "forward (dst) rule already present"
elif iptables -A FORWARD -d "$POOL" -j ACCEPT 2>/dev/null; then
    log "added FORWARD ACCEPT -d $POOL"
else
    log "WARN: failed to add FORWARD (dst) rule - host likely lacks NET_ADMIN"
fi

exit 0
