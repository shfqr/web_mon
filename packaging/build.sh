#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:-}
VERSION=$(cat VERSION 2>/dev/null || echo "0.0.0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
DIST="$ROOT/dist"
mkdir -p "$DIST"

usage() {
  echo "Usage: $0 {deb|rpm|arch|apk}" >&2
  exit 1
}

case "$TARGET" in
  deb)
    echo "# Build Debian package inside container"
    echo "docker run --rm -v $ROOT:/src -w /src debian:stable bash -c 'apt-get update && apt-get install -y build-essential devscripts debhelper && cd packaging/deb && debuild -us -uc'"
    ;;
  rpm)
    echo "# Build RPM inside container"
    echo "docker run --rm -v $ROOT:/src -w /src fedora:latest bash -c 'dnf install -y rpm-build make gcc && rpmbuild -bb packaging/rpm/webmon.spec --define \"_sourcedir /src\" --define \"_version $VERSION\"'"
    ;;
  arch)
    echo "# Build Arch package inside container"
    echo "docker run --rm -v $ROOT:/src -w /src archlinux:base bash -c 'pacman -Sy --noconfirm base-devel && cd packaging/arch && makepkg -sf'"
    ;;
  apk)
    echo "# Build Alpine package inside container"
    echo "docker run --rm -v $ROOT:/src -w /src alpine:latest sh -c 'apk add --no-cache build-base abuild && cd packaging/alpine && abuild -F'"
    ;;
  *) usage ;;
esac
