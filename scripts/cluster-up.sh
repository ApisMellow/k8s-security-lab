#!/usr/bin/env bash
# NOTE: This script is deprecated. Use the Makefile instead:
#   make up        - create basic cluster
#   make up-audit  - create hardened cluster with audit logging
set -euo pipefail
NAME="${1:-dev}"
echo "[+] Creating k3d cluster '$NAME' with 1 server and 2 agents..."
k3d cluster create "$NAME" --agents 2
echo "[+] kubeconfig set. Verifying..."
kubectl cluster-info
kubectl get nodes -o wide
