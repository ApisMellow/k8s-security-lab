#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-dev}"
echo "[-] Deleting existing cluster (if any) named '$NAME'..."
k3d cluster delete "$NAME" || true

# Ensure manifests path
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/manifests/audit-policy.yaml"

echo "[+] Creating k3d cluster '$NAME' with API audit logging enabled..."
k3d cluster create "$NAME" \
  --image rancher/k3s:v1.30.4-k3s1 \
  --api-port 127.0.0.1:6445 \
  --agents 2 \
  --volume "${POLICY}:/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-policy-file=/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxage=5@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxbackup=5@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxsize=10@server:0"

echo "[+] Cluster created. Verifying..."
kubectl cluster-info
kubectl get nodes -o wide
