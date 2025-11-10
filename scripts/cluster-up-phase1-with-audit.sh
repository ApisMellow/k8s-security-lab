#!/usr/bin/env bash
# Phase 1: Cluster creation with API audit logging enabled
#
# This is the MANUAL PATH for Phase 1 with audit logging. Use this to understand each step.
# For the automated path, use the Makefile: make phase1
#
# This creates a k3d cluster with:
#   - API audit logging enabled
#   - Audit policy mounted from manifests/audit-policy.yaml
#   - Audit logs written to /var/lib/rancher/k3s/server/logs/audit.log
#   - Stable K3s version (v1.30.4-k3s1)
#   - API bound to localhost:6445 (explicit binding)
#
# Usage:
#   ./scripts/cluster-up-phase1-with-audit.sh              # creates cluster named 'dev'
#   ./scripts/cluster-up-phase1-with-audit.sh myenv        # creates cluster named 'myenv'
#
# This will DELETE any existing cluster with the same name first.

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

echo "[+] Cluster created. Setting kubectl context..."
kubectl config use-context "k3d-$NAME"

echo "[+] Verifying..."
kubectl cluster-info
kubectl get nodes -o wide

echo ""
echo "Next steps:"
echo "  1) Apply namespaces:    kubectl apply -f manifests/namespaces.yaml"
echo "  2) Apply RBAC:          kubectl apply -f manifests/rbac-dev-view.yaml"
echo "  3) Verify permissions:  bash scripts/harden-phase1.sh"
