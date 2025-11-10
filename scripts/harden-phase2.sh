#!/usr/bin/env bash
set -euo pipefail

# Phase 2 Hardening: PSA + Kyverno baseline → enforce
# Flags:
#   --enforce     : switch Kyverno policies from audit -> enforce
#   --namespace X : target app namespace (default: dev)
#
# Usage:
#   ./scripts/harden-phase2.sh
#   ./scripts/harden-phase2.sh --enforce
#   ./scripts/harden-phase2.sh --namespace prod --enforce

NS="dev"
ACTION="audit"   # default Kyverno validationFailureAction

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enforce) ACTION="enforce"; shift ;;
    --namespace) NS="$2"; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

ok()   { printf "✅ %s\n" "$*"; }
warn() { printf "⚠️  %s\n" "$*"; }
err()  { printf "❌ %s\n" "$*"; }

header() {
  echo ""
  echo "---------------------------------------------"
  echo "$1"
  echo "---------------------------------------------"
}

# 0) Sanity: context and nodes
header "Context & Health"
ctx="$(kubectl config current-context 2>/dev/null || true)"
[[ -z "$ctx" ]] && err "kubectl has no current-context (set KUBECONFIG)"
echo "Context: $ctx"
kubectl get nodes -o wide
ok "Cluster reachable"

# 1) PSA labels
header "Pod Security Admission labels"
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS" >/dev/null
kubectl label ns "$NS" pod-security.kubernetes.io/enforce=baseline --overwrite >/dev/null
ok "Namespace '$NS' labeled: enforce=baseline"
if kubectl get ns prod >/dev/null 2>&1; then
  kubectl label ns prod pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
  ok "Namespace 'prod' labeled: enforce=restricted"
fi
kubectl get ns "$NS" --show-labels

# 2) Kyverno install (if missing)
header "Kyverno installation"
if ! kubectl get ns kyverno >/dev/null 2>&1; then
  helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
  helm repo update >/dev/null
  helm install kyverno kyverno/kyverno -n kyverno --create-namespace
  ok "Kyverno installed via Helm"
else
  echo "Kyverno namespace exists — skipping install"
fi

# Wait for Kyverno deployments to be ready
# Note: Kyverno 3.5+ uses multiple controllers (admission, background, cleanup, reports)
echo "Waiting for Kyverno controllers to be ready..."
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=180s || {
  err "Kyverno admission controller did not reach ready state. Check logs with: kubectl -n kyverno logs deploy/kyverno-admission-controller"
  exit 1
}
kubectl -n kyverno get pods

# 3) Create/update baseline policies (or update) in ./policies/phase-2-baseline
header "Applying Kyverno baseline policies (validationFailureAction=${ACTION})"

POL_DIR="./policies/phase-2-baseline"
mkdir -p "${POL_DIR}"

# ---- Validation: Disallow Privileged
cat > "${POL_DIR}/disallow-privileged.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: privileged-containers
      match:
        resources:
          kinds: ["Pod"]
      validate:
        message: "Privileged containers are not allowed"
        pattern:
          spec:
            containers:
            - =(securityContext):
                =(privileged): false
YAML

# ---- Validation: Disallow Root User
cat > "${POL_DIR}/disallow-root-user.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-root-user
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: require-nonroot
      match:
        resources:
          kinds: ["Pod"]
      validate:
        message: "Containers must not run as root (runAsNonRoot: true)"
        anyPattern:
          - spec:
              securityContext:
                runAsNonRoot: true
          - spec:
              containers:
              - =(securityContext):
                  =(runAsUser): ">0"
YAML

# ---- Validation: Restrict Image Registry
cat > "${POL_DIR}/restrict-image-registry.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registry
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: allowed-registries
      match:
        resources:
          kinds: ["Pod"]
      validate:
        message: "Images must come from allowed registries (ghcr.io/* or docker.io/library/*)"
        foreach:
        - list: "request.object.spec.containers"
          deny:
            conditions:
            - key: "{{ element.image }}"
              operator: NotIn
              value:
              - docker.io/library/*
              - ghcr.io/*
YAML

# ---- Validation: Require Labels
cat > "${POL_DIR}/require-labels.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: require-app-label
      match:
        resources:
          kinds: ["Pod","Deployment","StatefulSet","DaemonSet","Job","CronJob"]
      validate:
        message: "Resource must include label 'app'"
        pattern:
          metadata:
            labels:
              app: "?*"
YAML

# ---- Validation: Disallow hostPath
cat > "${POL_DIR}/disallow-hostpath.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-hostpath
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: forbid-hostpath-volumes
      match:
        resources:
          kinds: ["Pod"]
      validate:
        message: "Use of hostPath volumes is disallowed."
        foreach:
          - list: "request.object.spec.volumes[]"
            deny:
              conditions:
                - key: "{{ element.hostPath }}"
                  operator: AnyNotIn
                  value:
                    - null
YAML

# ---- Mutation: Drop NET_RAW capability unless annotated
cat > "${POL_DIR}/drop-net-raw-capability.yaml" <<'YAML'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: drop-net-raw-capability
spec:
  validationFailureAction: PLACEHOLDER_ACTION
  background: true
  rules:
    - name: add-drop-net-raw-containers
      match:
        resources:
          kinds: ["Pod"]
      mutate:
        foreach:
          - list: "request.object.spec.containers[]"
            patchStrategicMerge:
              spec:
                containers:
                  - name: "{{ element.name }}"
                    securityContext:
                      capabilities:
                        drop:
                          - NET_RAW
          - list: "request.object.spec.initContainers[]"
            patchStrategicMerge:
              spec:
                initContainers:
                  - name: "{{ element.name }}"
                    securityContext:
                      capabilities:
                        drop:
                          - NET_RAW
YAML

# Replace placeholder action with chosen ACTION (audit/enforce)
for f in "${POL_DIR}/"*.yaml; do
  sed -i.bak "s/PLACEHOLDER_ACTION/${ACTION}/g" "$f" || true
  rm -f "$f.bak" || true
done

kubectl apply -f "${POL_DIR}/"
kubectl get clusterpolicies

# 4) Demonstrate policy behavior
header "Policy behavior demo (namespace=${NS}, action=${ACTION})"
# Non-compliant pod: privileged + root user
set +e
out=$(kubectl -n "$NS" run p2-test --image=nginx --overrides='{"spec":{"securityContext":{"runAsNonRoot":false},"containers":[{"name":"c","image":"nginx","securityContext":{"privileged":true,"runAsUser":0}}]}}' 2>&1)
rc=$?
set -e
echo "$out" | sed 's/^/  /'

if [[ "$ACTION" == "enforce" ]]; then
  if [[ $rc -ne 0 ]] && echo "$out" | grep -qiE "forbidden|denied|violation|blocked"; then
    ok "Enforce: non-compliant pod was blocked as expected"
  else
    err "Enforce: expected rejection but command did not fail"; exit 1
  fi
else
  ok "Audit: non-compliant pod admitted (or attempted) — should appear in PolicyReports"
fi

# Clean up stray pod if created in audit mode
kubectl -n "$NS" delete pod p2-test --ignore-not-found=true >/dev/null 2>&1 || true

# 5) Show policy reports (requires kyverno-reports-controller; otherwise skip gracefully)
header "Policy reports (summary)"
kubectl get policyreport -A -o wide || true
kubectl get clusterpolicyreport -A -o wide || true

echo ""
ok "Phase 2 hardening complete (ACTION=${ACTION})."
echo "Tip: rerun with --enforce to turn audit findings into hard blocks."
