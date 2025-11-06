#!/usr/bin/env bash
set -euo pipefail

NS_LIST=("dev" "prod")
echo "==> Deleting Phase 3 NetworkPolicies from dev/prod"
for ns in "${NS_LIST[@]}"; do
  kubectl -n "$ns" delete -f network-policies/ --ignore-not-found=true
done

echo "==> Optional: nuke extra per-app policies"
for ns in "${NS_LIST[@]}"; do
  kubectl -n "$ns" delete networkpolicy allow-app-to-app allow-egress-external \
    --ignore-not-found=true
done

echo "==> Phase 3 reset complete."

