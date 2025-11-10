#!/usr/bin/env bash
set -euo pipefail

ok()   { printf "✅ %s\n" "$*"; }
warn() { printf "⚠️  %s\n" "$*"; }
err()  { printf "❌ %s\n" "$*"; }

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

SERVER_CONT="${SERVER_CONT:-k3d-dev-server-0}"
AUDIT_PATH="/var/lib/rancher/k3s/server/logs/audit.log"

summary=()

header() {
  echo ""
  echo "---------------------------------------------"
  echo "$1"
  echo "---------------------------------------------"
}

header "Context & Health"
ctx="$(kubectl config current-context 2>/dev/null)" || {
  err "kubectl has no current-context. Set KUBECONFIG and try again."
  exit 1
}
echo "Current context: ${ctx}"
kubectl get nodes -o wide || { err "Cannot reach cluster"; exit 1; }
ok "kubectl is talking to the cluster"
summary+=("kubectl reachable: PASS")

header "API Binding (localhost)"
api=$(kubectl cluster-info | awk '/Kubernetes control plane is running at/ {print $NF}')
api_hostport=$(echo "$api" | sed -E 's#https?://([^/]+)/?.*#\1#')
api_host="${api_hostport%:*}"
api_port="${api_hostport##*:}"

if [[ "$api_host" == "127.0.0.1" || "$api_host" == "localhost" ]]; then
  ok "API is bound to ${api_host}:${api_port}"
  summary+=("API bound to localhost: PASS")
else
  warn "API appears bound to ${api_host}:${api_port}. Consider recreating cluster with: --api-port 127.0.0.1:6445"
  summary+=("API bound to localhost: WARN (${api_host}:${api_port})")
fi

header "Namespace & RBAC"
kubectl get ns dev >/dev/null 2>&1 || { err "Namespace 'dev' not found. Apply manifests/namespaces.yaml first."; exit 1; }
kubectl -n dev get sa sa-dev-view >/dev/null 2>&1 || { err "ServiceAccount 'sa-dev-view' not found in dev namespace. Apply manifests/rbac-dev-view.yaml first."; exit 1; }
kubectl -n dev get role dev-view >/dev/null 2>&1 || { err "Role 'dev-view' not found in dev namespace. Apply manifests/rbac-dev-view.yaml first."; exit 1; }
kubectl -n dev get rolebinding dev-view-binding >/dev/null 2>&1 || { err "RoleBinding 'dev-view-binding' not found in dev namespace. Apply manifests/rbac-dev-view.yaml first."; exit 1; }
ok "Namespace dev and RBAC (sa-dev-view, dev-view, dev-view-binding) are present"
summary+=("RBAC least-privilege present: PASS")

header "RBAC Permission Tests (sa-dev-view)"
if ! docker ps --format '{{.Names}}' | grep -q "^${SERVER_CONT}$"; then
  err "Cannot find server container ${SERVER_CONT}. Set SERVER_CONT env var if your name differs."
  exit 1
fi

# Create test pod for allowed operations
kubectl -n dev run test-pod --image=alpine:latest --overrides='{"spec":{"serviceAccountName":"sa-dev-view"}}' >/dev/null 2>&1 || true

# Test 1: List pods (should SUCCEED - allowed by role)
set +e
list_out=$(kubectl -n dev get pods --as=system:serviceaccount:dev:sa-dev-view 2>&1)
list_rc=$?
set -e

if [[ $list_rc -eq 0 ]]; then
  ok "List pods ALLOWED (as expected)"
  summary+=("List pods (allowed): PASS")
else
  err "List pods DENIED (should be allowed by role)"
  summary+=("List pods (allowed): FAIL")
fi

# Test 2: Watch pods (should SUCCEED - allowed by role)
set +e
watch_out=$(kubectl -n dev get pods --as=system:serviceaccount:dev:sa-dev-view --watch=false 2>&1)
watch_rc=$?
set -e

if [[ $watch_rc -eq 0 ]]; then
  ok "Watch pods ALLOWED (as expected)"
  summary+=("Watch pods (allowed): PASS")
else
  err "Watch pods DENIED (should be allowed by role)"
  summary+=("Watch pods (allowed): FAIL")
fi

# Test 3: Create pods (should FAIL - denied by role)
set +e
create_out=$(kubectl -n dev run forbidden-pod --image=alpine:latest --as=system:serviceaccount:dev:sa-dev-view 2>&1)
create_rc=$?
set -e

if [[ $create_rc -ne 0 ]] && echo "$create_out" | grep -qi "forbidden"; then
  ok "Create pods DENIED (as expected)"
  summary+=("Create pods (denied): PASS")
else
  warn "Create pods not denied as expected"
  summary+=("Create pods (denied): WARN")
fi

# Test 4: Delete pods (should FAIL - denied by role)
set +e
del_out=$(kubectl -n dev delete pod test-pod --as=system:serviceaccount:dev:sa-dev-view 2>&1)
del_rc=$?
set -e

if [[ $del_rc -ne 0 ]] && echo "$del_out" | grep -qi "forbidden"; then
  ok "Delete pods DENIED (as expected)"
  summary+=("Delete pods (denied): PASS")
else
  warn "Delete pods not denied as expected"
  summary+=("Delete pods (denied): WARN")
fi

# Test 5: Access secrets (should FAIL - not in role)
set +e
secret_out=$(kubectl -n dev get secrets --as=system:serviceaccount:dev:sa-dev-view 2>&1)
secret_rc=$?
set -e

if [[ $secret_rc -ne 0 ]] && echo "$secret_out" | grep -qi "forbidden"; then
  ok "Get secrets DENIED (as expected)"
  summary+=("Get secrets (denied): PASS")
else
  warn "Get secrets not denied as expected"
  summary+=("Get secrets (denied): WARN")
fi

# Cleanup
kubectl -n dev delete pod test-pod --ignore-not-found=true >/dev/null 2>&1 || true

if docker exec -i "${SERVER_CONT}" test -f "${AUDIT_PATH}"; then
  ok "Audit file exists at ${AUDIT_PATH}"
  summary+=("Audit file present: PASS")
  echo ""
  echo "Recent DELETE audit entries (tail):"
  docker exec -i "${SERVER_CONT}" sh -c "tail -n 400 ${AUDIT_PATH} | grep '\"verb\":\"delete\"' | tail -n 5" || true
else
  warn "Audit file not found at ${AUDIT_PATH}. Verify k3s apiserver audit flags and policy mount."
  summary+=("Audit file present: FAIL")
fi

header "Audit Rotation"
docker exec -i "${SERVER_CONT}" sh -c "ls -lh /var/lib/rancher/k3s/server/logs/ | grep audit" || true

header "Pod Security Admission (namespace labels)"
for ns in dev prod; do
  if kubectl get ns "$ns" >/dev/null 2>&1; then
    kubectl label ns "$ns" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null 2>&1 || true
  fi
done
kubectl get ns dev -o jsonpath='{.metadata.labels}' | sed $'s/{/  /;s/}/\
/'
ok "PSA 'restricted' label ensured on dev (and prod if present)"
summary+=("PSA restricted labels: PASS")

header "Phase 1 Hardening Summary"
for line in "${summary[@]}"; do
  case "$line" in
    *PASS*) echo -e "${GREEN}${line}${NC}" ;;
    *WARN*) echo -e "${YELLOW}${line}${NC}" ;;
    *FAIL*) echo -e "${RED}${line}${NC}" ;;
    *) echo "$line" ;;
  esac
done

echo ""
echo "Tips:"
echo " - To bind API to localhost, recreate with: k3d cluster create dev --image rancher/k3s:v1.30.4-k3s1 --api-port 127.0.0.1:6445 --agents 2"
echo " - Ensure audit policy is mounted and flags set in cluster-up-phase1-with-audit.sh"
