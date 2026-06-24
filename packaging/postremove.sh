#!/bin/sh
# Package postremove: reload systemd. /etc/tiredvpn (cert, key, secret) is left
# in place on purpose so a reinstall keeps the same identity; remove it by hand
# if you really want a clean slate.
set -e

systemctl daemon-reload 2>/dev/null || true
