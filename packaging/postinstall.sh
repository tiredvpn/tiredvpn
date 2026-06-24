#!/bin/sh
# Package postinstall: register the unit, seed the env file, point the user at
# tiredvpn-init. Deliberately does NOT generate a secret, enable, or start the
# service - that needs the public IP and a deliberate operator action.
set -e

systemctl daemon-reload 2>/dev/null || true

if [ ! -f /etc/tiredvpn/env ] && [ -f /etc/tiredvpn/env.example ]; then
  cp /etc/tiredvpn/env.example /etc/tiredvpn/env
  chmod 0600 /etc/tiredvpn/env
fi
chmod 0750 /etc/tiredvpn 2>/dev/null || true

echo "TiredVPN installed. Finish setup with: sudo tiredvpn-init"
