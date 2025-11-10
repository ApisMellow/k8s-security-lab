#!/usr/bin/env bash
set -euo pipefail

echo "==> Applying Kyverno policies for Phase 4"
kubectl apply -f policies/phase-4-secrets/disallow-env-secrets.yaml
kubectl apply -f policies/phase-4-secrets/require-secret-names.yaml
kubectl apply -f policies/phase-4-secrets/warn-sensitive-configmap.yaml

echo "==> Creating test secret (must match naming policy: include 'secret-' or '-secret-')"
kubectl -n default create secret generic enc-test-secret --from-literal=top=secret --dry-run=client -o yaml | kubectl apply -f -

echo "==> Done. Check with: kubectl get cpol,pol -A"
echo "==> Verify secret was created: kubectl get secret -n default enc-test-secret"
