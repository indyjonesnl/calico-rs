#!/usr/bin/env bash
# Build the calico-rs node image and load it into the kind cluster.
#
# Binaries are built statically against musl (the kind nodes run Debian
# bookworm/glibc 2.36, older than the host, so a static binary avoids the glibc
# mismatch). The image just copies them in.
#
# Usage: scripts/build-image.sh [--load]
#   --load   also `kind load` the image into the calico-rs-kind cluster
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${CALICO_RS_IMAGE:-calico-rs:dev}"
TARGET="x86_64-unknown-linux-musl"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/$TARGET/release"
CTX="$REPO_ROOT/deploy/.build"

echo ">> building static binaries ($TARGET)"
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --target "$TARGET" \
    -p node        --bin calico-rs-node \
    -p controllers --bin calico-rs-controllers \
    -p cni         --bin calico

echo ">> staging build context: $CTX"
rm -rf "$CTX"
mkdir -p "$CTX"
cp "$TARGET_DIR/calico-rs-node"        "$CTX/"
cp "$TARGET_DIR/calico-rs-controllers" "$CTX/"
cp "$TARGET_DIR/calico"                "$CTX/"
cp "$REPO_ROOT/deploy/Dockerfile"      "$CTX/"

echo ">> docker build $IMAGE"
docker build -t "$IMAGE" "$CTX"
rm -rf "$CTX"

if [[ "${1:-}" == "--load" ]]; then
  echo ">> kind load $IMAGE"
  kind load docker-image --name calico-rs-kind "$IMAGE"
fi
echo ">> done: $IMAGE"
