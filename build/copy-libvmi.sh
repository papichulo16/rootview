#!/usr/bin/env bash
# pulls libvmi's shared libraries out of the built docker image and drops
# them next to the `rv` binary, where the Makefile's $ORIGIN rpath looks for
# them. only needed if the host isn't already running its own bare-metal
# libvmi build - see README.
set -euo pipefail

IMAGE="${1:-rootview}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d)"
container="$(docker create "$IMAGE")"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

docker cp "$container:/usr/local/lib/." "$tmp"

copied=0
for f in "$tmp"/libvmi.so*; do
    [ -e "$f" ] || continue
    cp -P "$f" "$REPO_ROOT/"
    copied=$((copied + 1))
done

if [ "$copied" -eq 0 ]; then
    echo "error: no libvmi.so* found in $IMAGE:/usr/local/lib - was it built with 'docker build build -t $IMAGE'?" >&2
    exit 1
fi

echo "copied $copied file(s) to $REPO_ROOT:"
ls -la "$REPO_ROOT"/libvmi.so*
