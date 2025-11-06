#!/usr/bin/env bash
set -euo pipefail

# Phase 2 Reset: remove Kyverno, policies, and PSA labels so Phase 2 starts "red"
# Flags:
#   --keep-kyverno   : keep Kyverno deployment, just remove policies & labels
#   --namespace X    : target app namespace to clear labels/pods (default: dev)

KEEP=false
NS="dev"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-kyverno) KEEP=true; shift ;;
    --namespace) NS="$2"; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

ok()   { printf "✅ %s\n" "$*"; }
info() { printf "ℹ️  %s\n" "$*"; }
warn() { printf "⚠️  %s\n" "$*"; }

header() {
  echo ""
  echo "---------------------------------------------"
  echo "$1"
  echo "---------------------------------------------"
}

header "Context"
kubectl config current-context || true

header "Delete Kyverno ClusterPolicies"
kubectl delete clusterpolicy disallow-privileged --ignore-not-found=true || true
kubectl delete clusterpolicy disallow-root-user --ignore-not-found=true || true
kubectl delete clusterpolicy restrict-image-registry --ignore-not-found=true || true
kubectl delete clusterpolicy require-labels --ignore-not-found=true || true
ok "Deleted ClusterPolicies (if present)"

header "Clear PolicyReports"
kubectl get policyreport -A --no-headers 2>/dev/null | awk '{print $1, $2}' | while read -r ns name; do
  kubectl -n "$ns" delete policyreport "$name" --ignore-not-found=true || true
done || true
kubectl get clusterpolicyreport -A --no-headers 2>/dev/null | awk '{print $1, $2}' | while read -r ns name; do
  kubectl -n "$ns" delete clusterpolicyreport "$name" --ignore-not-found=true || true
done || true
ok "Cleared PolicyReports (if CRDs present)"

header "Remove PSA labels from namespaces"
for tgt in "$NS" prod; do
  if kubectl get ns "$tgt" >/dev/null 2>&1; then
    kubectl label ns "$tgt" pod-security.kubernetes.io/enforce- >/dev/null 2>&1 || true
    kubectl label ns "$tgt" pod-security.kubernetes.io/audit- >/dev/null 2>&1 || true
    kubectl label ns "$tgt" pod-security.kubernetes.io/warn- >/dev/null 2>&1 || true
    ok "Cleared PSA labels from namespace $tgt"
  fi
done

header "Delete test pods"
kubectl -n "$NS" delete pod p2-test --ignore-not-found=true || true

if ! $KEEP; then
  header "Uninstall Kyverno"
  if kubectl get ns kyverno >/dev/null 2>&1; then
    helm uninstall kyverno -n kyverno || true
    kubectl delete ns kyverno --ignore-not-found=true || true
    ok "Kyverno removed"
  else
    info "Kyverno namespace not present"
  fi
else
  info "Keeping Kyverno deployment (per --keep-kyverno)"
fi

header "Clean local policy files (./policies)"
rm -f ./policies/disallow-privileged.yaml \
      ./policies/disallow-root-user.yaml \
      ./policies/restrict-image-registry.yaml \
      ./policies/require-labels.yaml 2>/dev/null || true
rmdir ./policies 2>/dev/null || true
ok "Local policy files cleaned"

echo ""
ok "Phase 2 reset complete. Re-run ./scripts/harden-phase2.sh to rebuild baseline."
