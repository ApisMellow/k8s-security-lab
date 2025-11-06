#!/usr/bin/env bash
# NOTE: This script is deprecated. Use the Makefile instead:
#   make down - delete cluster
set -euo pipefail
NAME="${1:-dev}"
echo "[-] Deleting k3d cluster '$NAME'..."
k3d cluster delete "$NAME"
