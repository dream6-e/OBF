#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=${OBF_RUST_PREFIX:-"$ROOT/.toolchains/rust-1.88.0"}

if [[ -x "$PREFIX/bin/rustc" && -x "$PREFIX/bin/cargo" && -x "$PREFIX/bin/rustfmt" ]] \
    && "$PREFIX/bin/rustc" --version | grep -q '^rustc 1\.88\.0 ' \
    && "$PREFIX/bin/cargo" --version | grep -q '^cargo 1\.88\.0 '; then
    printf '[rust] already installed at %s\n' "$PREFIX"
    exit 0
fi

command -v npm >/dev/null || {
    echo 'error: npm is required to install the pinned @rustbin packages' >&2
    exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rm -rf "$PREFIX"
mkdir -p "$PREFIX"

packages=(
    '@rustbin/rustc-1.88.0-x86_64-unknown-linux-gnu'
    '@rustbin/rust-std-1.88.0-x86_64-unknown-linux-gnu'
    '@rustbin/cargo-1.88.0-x86_64-unknown-linux-gnu'
    '@rustbin/rustfmt-1.88.0-x86_64-unknown-linux-gnu'
)

for package in "${packages[@]}"; do
    printf '[rust] fetching %s\n' "$package"
    archive=$(cd "$tmp" && npm pack "$package" --silent)
    rm -rf "$tmp/package"
    tar -xzf "$tmp/$archive" -C "$tmp"
    "$tmp/package/install.sh" --prefix="$PREFIX" --disable-ldconfig >/dev/null
    rm -rf "$tmp/package" "$tmp/$archive"
done

"$PREFIX/bin/rustc" --version
"$PREFIX/bin/cargo" --version
