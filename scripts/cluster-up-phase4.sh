#!/usr/bin/env bash
# Phase 4: Cluster creation with secrets encryption at rest + API audit logging
#
# This is the MANUAL PATH for Phase 4. Use this to understand each step.
# For the automated path, use the Makefile: make phase4
#
# This creates a new k3d cluster with:
#   - Secrets encryption at rest (K3s built-in provider, AES-GCM)
#   - API audit logging enabled
#   - Audit policy mounted from manifests/audit-policy.yaml
#   - Stable K3s version (v1.30.4-k3s1)
#   - API bound to localhost:6445 (explicit binding)
#
# Usage:
#   ./scripts/cluster-up-phase4.sh              # creates cluster named 'phase4'
#   ./scripts/cluster-up-phase4.sh prod         # creates cluster named 'prod'
#   AGENTS=3 ./scripts/cluster-up-phase4.sh     # creates cluster with 3 agents
#
# This will DELETE any existing cluster with the same name first.
# Requirements: k3d, docker, kubectl

set -euo pipefail

err() { printf "❌ %s\n" "$*" >&2; }

NAME="${1:-phase4}"
AGENTS="${AGENTS:-2}"

# Ensure manifests path
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/manifests/audit-policy.yaml"

if [[ ! -f "$POLICY" ]]; then
  echo "ERROR: Audit policy not found at $POLICY"
  exit 1
fi

echo "[-] Deleting existing cluster (if any) named '$NAME'..."
k3d cluster delete "$NAME" || true

echo "[+] Creating k3d cluster '$NAME' with secrets encryption + audit logging..."
k3d cluster create "$NAME" \
  --image rancher/k3s:v1.30.4-k3s1 \
  --api-port 127.0.0.1:6445 \
  --agents "$AGENTS" \
  --volume "${POLICY}:/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--secrets-encryption@server:*" \
  --k3s-arg "--kube-apiserver-arg=audit-policy-file=/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxage=5@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxbackup=5@server:0" \
  --k3s-arg "--kube-apiserver-arg=audit-log-maxsize=10@server:0"

echo "[+] Cluster created. Setting kubectl context..."
kubectl config use-context "k3d-$NAME"

echo "[+] Waiting for nodes to be Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=180s || {
  err "Nodes did not become Ready within 180s. Cluster may have failed to start."
  exit 1
}

echo "[+] Cluster verification..."
kubectl cluster-info
kubectl get nodes -o wide

echo "[+] Phase 4 cluster '$NAME' up with secrets encryption + audit logging enabled."
