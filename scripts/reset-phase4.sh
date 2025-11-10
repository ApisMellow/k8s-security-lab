#!/usr/bin/env bash
set -euo pipefail

echo "==> Deleting Phase 4 Kyverno policies from the cluster (not repo files)"
kubectl delete -f kyverno-policies/ --ignore-not-found

echo "==> Deleting test objects"
kubectl -n default delete secret enc-test --ignore-not-found

echo "Phase 4 reset complete (cluster resources only)."
