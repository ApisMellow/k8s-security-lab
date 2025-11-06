#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-dev}"
echo "[+] Creating k3d cluster '$NAME' with 1 server and 2 agents..."
k3d cluster create "$NAME" --agents 2
echo "[+] kubeconfig set. Verifying..."
kubectl cluster-info
kubectl get nodes -o wide
