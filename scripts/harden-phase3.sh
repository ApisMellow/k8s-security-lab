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
metadata: { name: _probe-deny-egress }
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

kubectl -n dev delete netpol _probe-deny-egress --ignore-not-found
kubectl -n dev delete pod np-probe --ignore-not-found

if [[ $EGRESS_STATUS -eq 0 ]]; then
  cat <<'MSG'
[!] It looks like your CNI may NOT be enforcing NetworkPolicy (egress worked under deny).
    Install a policy-aware CNI (Calico or Cilium) and re-run.
MSG
  # Continue anyway so you can install policies after enabling CNI.
fi

echo "==> Applying default-deny + allow rules (dev & prod)"
for ns in "${NS_LIST[@]}"; do
  for f in 00-default-deny-ingress.yaml 01-default-deny-egress.yaml 10-allow-dns-egress.yaml 20-allow-same-namespace.yaml; do
    kubectl -n "$ns" apply -f "network-policies/$f"
  done
  # app-to-app and external egress are optional / per-app
done

echo "==> Phase 3 baseline applied."
echo "   - default deny ingress/egress"
echo "   - DNS egress allowed"
echo "   - intra-namespace ingress allowed"
echo "Use 30-allow-app-to-app.yaml and 40-allow-egress-external.yaml per workload."

