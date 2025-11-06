#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-dev}"
echo "[-] Deleting k3d cluster '$NAME'..."
k3d cluster delete "$NAME"
