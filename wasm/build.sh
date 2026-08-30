#!/usr/bin/env bash
# Build the browser and Node verifiers and install them into Lodestar's public/tattler.
#
# This exists because the artefacts were previously produced by hand, and a hand-built artefact is
# how the shipped verifier goes stale against the Rust it came from. When that happened the page
# verified by yesterday's rules while the CLI used today's, and a stale build reported a *forgery*
# on an honest receipt, which is the worst answer a verifier can give. Lodestar pins the shipped
# binary against frozen receipts of every shape; this script is the other half, so that rebuilding
# is one command rather than a remembered sequence.
#
# Usage: wasm/build.sh [path-to-lodestar]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
dest="${1:-$root/../lodestar}/public/tattler"

[ -d "$dest" ] || { echo "no such directory: $dest" >&2; exit 1; }

cd "$root"
cargo build --release --target wasm32-unknown-unknown --manifest-path wasm/Cargo.toml
raw="target/wasm32-unknown-unknown/release/tattler_wasm.wasm"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

wasm-bindgen --target web    --out-dir "$tmp/web"  --no-typescript "$raw"
wasm-bindgen --target nodejs --out-dir "$tmp/node" --no-typescript "$raw"

# The two targets differ only in their JS glue; the module itself is the same compiled Rust. Assert
# that rather than assume it, because shipping one .wasm for two loaders is only safe if it is true.
if ! cmp -s "$tmp/web/tattler_wasm_bg.wasm" "$tmp/node/tattler_wasm_bg.wasm"; then
  echo "the web and node builds produced different .wasm files; they can no longer share one" >&2
  exit 1
fi

cp "$tmp/web/tattler_wasm.js"        "$dest/tattler_wasm.js"
cp "$tmp/web/tattler_wasm_bg.wasm"   "$dest/tattler_wasm_bg.wasm"
cp "$tmp/node/tattler_wasm.js"       "$dest/tattler_wasm_node.cjs"

echo "installed into $dest:"
ls -l "$dest"
echo
echo "Now run Lodestar's suite. The staleness guard there is the thing that decides whether this"
echo "build is shippable, and it has caught a bad one before."
