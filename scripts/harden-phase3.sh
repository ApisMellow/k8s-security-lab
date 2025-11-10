#!/usr/bin/env bash
set -euo pipefail

NS_LIST=("dev" "prod")

echo "==> Verifying namespaces exist"
for ns in "${NS_LIST[@]}"; do
  kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create ns "$ns"
done

echo "==> Smoke-test: does CNI enforce NetworkPolicies?"
# Create a quick deny policy in dev and check if a new busybox loses egress
kubectl -n dev apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: probe-deny-egress }
spec:
  podSelector: {}
  policyTypes: ["Egress"]
YAML

kubectl -n dev run np-probe --image=busybox --restart=Never -- sh -lc 'sleep 600' || true
echo "Waiting for np-probe to be Running..."
kubectl -n dev wait --for=condition=Ready pod/np-probe --timeout=90s || true

echo "Trying to curl a public site (should FAIL if egress is denied)..."
set +e
kubectl -n dev exec np-probe -- sh -lc 'wget -qO- https://example.com || echo FAIL'
EGRESS_STATUS=$?
set -e

kubectl -n dev delete netpol probe-deny-egress --ignore-not-found
kubectl -n dev delete pod np-probe --ignore-not-found

if [[ $EGRESS_STATUS -eq 0 ]]; then
  cat <<'MSG'
[!] It looks like your CNI may NOT be enforcing NetworkPolicy (egress worked under deny).
    Install a policy-aware CNI (Calico or Cilium) and re-run.
MSG
  # Continue anyway so you can install policies after enabling CNI.
fi

echo "==> Applying NetworkPolicies (dev & prod)"
for ns in "${NS_LIST[@]}"; do
  echo "Applying to namespace: $ns"
  for f in 00-default-deny-ingress.yaml 01-default-deny-egress.yaml 10-allow-dns-egress.yaml 20-allow-same-namespace.yaml 30-allow-app-to-app.yaml 40-allow-egress-external.yaml; do
    # Replace namespace in the policy
    sed "s/namespace: dev/namespace: $ns/g" "network-policies/$f" | kubectl apply -f -
  done
done

echo "==> Phase 3 baseline applied."
echo "   - default deny ingress/egress"
echo "   - DNS egress allowed"
echo "   - intra-namespace ingress allowed"
echo "   - app-to-app communication allowed"
echo "   - external HTTPS egress allowed"
echo ""
echo "⚠️  IMPORTANT: Phase 4 requires a NEW cluster with encryption at rest."
echo "Before running 'make phase4', you MUST stop this cluster:"
echo "   make cluster-down"
echo ""
echo "Phase 4 will create a fresh cluster (also on port 127.0.0.1:6445)"

