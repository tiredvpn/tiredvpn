#!/usr/bin/env bash
#
# Build .deb and .rpm for amd64 and arm64 with nfpm.
#
# Requires: nfpm in PATH, and the per-arch binaries tiredvpn-linux-amd64 and
# tiredvpn-linux-arm64 present in the current directory (as produced by the
# release build). Reads VERSION from the environment. Output goes to ./dist.
set -euo pipefail

VERSION="${VERSION:?set VERSION (e.g. 1.3.3)}"
mkdir -p dist

for arch in amd64 arm64; do
  if [ ! -f "tiredvpn-linux-${arch}" ]; then
    echo "missing binary tiredvpn-linux-${arch}" >&2
    exit 1
  fi
  # nfpm.yaml references a fixed ./tiredvpn (env vars don't expand in src).
  cp "tiredvpn-linux-${arch}" tiredvpn
  for pkg in deb rpm; do
    echo "==> nfpm ${pkg} ${arch} ${VERSION}"
    VERSION="$VERSION" ARCH="$arch" nfpm package --config nfpm.yaml --packager "$pkg" --target dist/
  done
  rm -f tiredvpn
done

ls -l dist/
