#!/bin/sh
# Package preremove: stop and disable the service on real removal, but not on
# upgrade. Arg conventions differ:
#   deb: $1 = remove | purge | upgrade
#   rpm: $1 = 0 (uninstall) | 1+ (upgrade)
set -e

case "${1:-}" in
  remove|purge|0)
    systemctl stop tiredvpn 2>/dev/null || true
    systemctl disable tiredvpn 2>/dev/null || true
    ;;
esac
