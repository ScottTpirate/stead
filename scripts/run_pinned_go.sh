#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required_version="go1.27.0"
archive_sha256="675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
binary_sha256="1db869c560a193573a71be466a34e0d4abb7792d78165c6102cdda069276a3a8"
cache_root="${STEAD_GO_TOOLCHAIN_CACHE:-/tmp/stead-go-toolchain-1.27.0}"
archive="$cache_root/go1.27.0.linux-amd64.tar.gz"
toolchain="$cache_root/toolchain/go"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'The verified foundation toolchain currently supports Linux amd64 only; approve and pin a platform archive before use.\n' >&2
  exit 1
fi

mkdir -p "$cache_root/toolchain"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --silent --show-error \
    https://go.dev/dl/go1.27.0.linux-amd64.tar.gz \
    --output "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --status
if [[ ! -x "$toolchain/bin/go" ]]; then
  tar --extract --gzip --file "$archive" --directory "$cache_root/toolchain"
fi
printf '%s  %s\n' "$binary_sha256" "$toolchain/bin/go" | sha256sum --check --status

export PATH="$toolchain/bin:$PATH"
export GOROOT="$toolchain"
export GOCACHE="${GOCACHE:-/tmp/stead-go-build-cache}"
export GOPATH="${GOPATH:-/tmp/stead-go-path}"
cd "$repo_root"
exec "$@"
