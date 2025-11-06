#!/usr/bin/env bash
set -euo pipefail
ok() { printf "✅ %s\n" "$*"; }
warn() { printf "⚠️  %s\n" "$*"; }

SERVER_CONT="${SERVER_CONT:-k3d-dev-server-0}"
CLUSTER_NAME="${CLUSTER_NAME:-dev}"
AUDIT_PATH="/var/lib/rancher/k3s/server/logs/audit.log"

case "${1:-}" in
  --insecure-recreate) insecure=true ;;
  *) insecure=false ;;
esac

echo "Resetting Phase 1 lab state…"

kubectl delete ns dev --ignore-not-found=true >/dev/null 2>&1
kubectl delete ns prod --ignore-not-found=true >/dev/null 2>&1
ok "Deleted lab namespaces"

if docker ps --format '{{.Names}}' | grep -q "$SERVER_CONT"; then
  docker exec -i "$SERVER_CONT" sh -c "rm -f $AUDIT_PATH || true"
  warn "Audit file removed"
fi

if $insecure; then
  warn "Recreating insecure cluster"
  k3d cluster delete "$CLUSTER_NAME" || true
  k3d cluster create "$CLUSTER_NAME" --image rancher/k3s:v1.30.4-k3s1 --agents 2
  ok "Cluster recreated with default settings"
fi

echo "Reset complete. Run ./scripts/harden-phase1.sh next to re-verify."

