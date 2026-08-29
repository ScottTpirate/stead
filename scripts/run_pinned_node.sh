#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required_version="v26.8.1"
archive_sha256="3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d"
binary_sha256="19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3"
cache_root="${STEAD_NODE_TOOLCHAIN_CACHE:-/tmp/stead-node-toolchain-26.8.1}"
archive="$cache_root/node-v26.8.1-linux-x64.tar.xz"
toolchain="$cache_root/toolchain/node-v26.8.1-linux-x64"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'The verified foundation toolchain currently supports Linux x64 only; approve and pin a platform archive before use.\n' >&2
  exit 1
fi

mkdir -p "$cache_root/toolchain"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --silent --show-error \
    https://nodejs.org/dist/v26.8.1/node-v26.8.1-linux-x64.tar.xz \
    --output "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --status
if [[ ! -x "$toolchain/bin/node" ]]; then
  tar --extract --xz --file "$archive" --directory "$cache_root/toolchain"
fi
printf '%s  %s\n' "$binary_sha256" "$toolchain/bin/node" | sha256sum --check --status

export PATH="$toolchain/bin:$PATH"
cd "$repo_root"
exec "$@"
