#!/usr/bin/env bash
# Helper script to build and execute benchmarks inside an Ubuntu ARM64 Docker container

set -euo pipefail

IMAGE_NAME="mem-benchmark-env"

echo "[*] Building Ubuntu ARM64 benchmarking container image..."
docker build -t "${IMAGE_NAME}" .

echo "[*] Running framework inside Ubuntu container..."
docker run --rm -it \
    -v "$(pwd)":/workspace \
    "${IMAGE_NAME}" "$@"
