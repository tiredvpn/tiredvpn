#!/bin/sh
# TiredVPN TUN server entrypoint.
#
# When started with `-ip-pool <CIDR>` (server TUN mode), this sets up NAT
# masquerading and forwarding so client traffic egresses through the host WAN.
# In proxy mode (no -ip-pool) it does nothing and just execs the binary.
#
# NAT setup needs NET_ADMIN (and ip_forward sysctl writable). If those are
# missing, we warn on stderr but do NOT fail — so proxy mode still works in
# this image too.
#
# Env overrides:
#   TIREDVPN_WAN_IFACE  — force WAN interface instead of autodetecting it.

set -u

BIN=/usr/local/bin/tiredvpn

log() {
    echo "[entrypoint] $*" >&2
}

# Extract the -ip-pool value from args. Supports both "-ip-pool 10.8.0.0/24"
# and "-ip-pool=10.8.0.0/24" forms.
POOL=""
prev=""
for arg in "$@"; do
    case "$arg" in
        -ip-pool=*|--ip-pool=*)
            POOL="${arg#*=}"
            ;;
        -ip-pool|--ip-pool)
            prev="ippool"
            continue
            ;;
        *)
            if [ "$prev" = "ippool" ]; then
                POOL="$arg"
            fi
            ;;
    esac
    prev=""
done

if [ -n "$POOL" ]; then
    log "server TUN mode detected (-ip-pool $POOL), configuring NAT"

    # Enable IPv4 forwarding. Needs a writable sysctl (privileged or
    # --sysctl net.ipv4.ip_forward=1). Warn but continue on failure.
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        log "WARN: could not set net.ipv4.ip_forward=1 — run container with --privileged or --sysctl net.ipv4.ip_forward=1"
    fi

    # Determine WAN interface: env override, else route to a public IP.
    WAN="${TIREDVPN_WAN_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}')}"

    if [ -z "$WAN" ]; then
        log "WARN: could not determine WAN interface (set TIREDVPN_WAN_IFACE) — skipping NAT setup"
    else
        log "using WAN interface: $WAN"

        # Idempotent rule install: check (-C) before append (-A).
        if iptables -t nat -C POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null; then
            log "nat POSTROUTING masquerade rule already present"
        elif iptables -t nat -A POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null; then
            log "added nat POSTROUTING MASQUERADE -s $POOL -o $WAN"
        else
            log "WARN: failed to add MASQUERADE rule — container likely lacks NET_ADMIN"
        fi

        if iptables -C FORWARD -s "$POOL" -j ACCEPT 2>/dev/null; then
            log "forward (src) rule already present"
        elif iptables -A FORWARD -s "$POOL" -j ACCEPT 2>/dev/null; then
            log "added FORWARD ACCEPT -s $POOL"
        else
            log "WARN: failed to add FORWARD (src) rule — container likely lacks NET_ADMIN"
        fi

        if iptables -C FORWARD -d "$POOL" -j ACCEPT 2>/dev/null; then
            log "forward (dst) rule already present"
        elif iptables -A FORWARD -d "$POOL" -j ACCEPT 2>/dev/null; then
            log "added FORWARD ACCEPT -d $POOL"
        else
            log "WARN: failed to add FORWARD (dst) rule — container likely lacks NET_ADMIN"
        fi
    fi
else
    log "proxy mode (no -ip-pool), skipping NAT setup"
fi

exec "$BIN" "$@"
