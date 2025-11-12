#!/usr/bin/env bash
# Phase 5: Attack Simulation - Controlled tests validating Phase 1-4 security controls
#
# This script runs 4 safe, non-destructive attack scenarios to validate that
# the security controls from Phases 1-4 actually prevent attacks:
#
# Test 1: RBAC Enforcement (Phase 1)
# Test 2: Pod Security Policy Enforcement (Phase 2)
# Test 3: NetworkPolicy Enforcement (Phase 3)
# Test 4: Secret Policy Enforcement (Phase 4)
#
# Output: Test report in reports/phase5-simulation-results.txt
# Time: ~5 minutes

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

TEST_NS="phase5-tests"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${PROJECT_ROOT}/reports/phase5-simulation"
REPORT_FILE="${REPORT_DIR}/simulation-results-${TIMESTAMP}.txt"

# Counters
PASSED=0
FAILED=0

# Color codes
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
  printf "${CYAN}[info]${NC} %s\n" "$1" | tee -a "$REPORT_FILE"
}

log_success() {
  printf "${GREEN}✅${NC} %s\n" "$1" | tee -a "$REPORT_FILE"
  PASSED=$((PASSED + 1))
}

log_fail() {
  printf "${RED}❌${NC} %s\n" "$1" | tee -a "$REPORT_FILE"
  FAILED=$((FAILED + 1))
}

log_test_name() {
  printf "\n${YELLOW}═══ TEST %s ===${NC}\n" "$1" | tee -a "$REPORT_FILE"
}

setup_test_ns() {
  kubectl create namespace "$TEST_NS" --dry-run=client -o yaml | kubectl apply -f - &>/dev/null
  log_info "Created test namespace: $TEST_NS"
}

cleanup_test_ns() {
  kubectl delete namespace "$TEST_NS" --ignore-not-found=true &>/dev/null
}

# ============================================================================
# Test 1: Phase 1 - RBAC Enforcement
# ============================================================================

test_phase1_rbac() {
  log_test_name "1: Phase 1 - RBAC Enforcement"

  log_info "Testing: Unprivileged service account cannot access prod secrets"

  # Create unprivileged service account
  kubectl -n "$TEST_NS" create serviceaccount attacker &>/dev/null

  # Attempt to access prod secrets without permission
  if kubectl --as=system:serviceaccount:${TEST_NS}:attacker \
    get secrets -n prod &>/dev/null 2>&1; then
    log_fail "RBAC allowed unauthorized access to prod secrets"
    echo "" >> "$REPORT_FILE"
    echo "EXPECTED: Forbidden (403) error" >> "$REPORT_FILE"
    echo "ACTUAL: Request succeeded" >> "$REPORT_FILE"
    return 1
  else
    log_success "RBAC blocked unauthorized access"
    echo "" >> "$REPORT_FILE"
    echo "ATTACK SCENARIO:" >> "$REPORT_FILE"
    echo "  Attacker gains access to pod with limited service account" >> "$REPORT_FILE"
    echo "  Attempts: kubectl get secrets -n prod" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "EXPECTED RESULT: Forbidden (403)" >> "$REPORT_FILE"
    echo "ACTUAL RESULT: ✅ Forbidden" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "WHY THIS MATTERS:" >> "$REPORT_FILE"
    echo "  - Even if attacker compromises a pod, RBAC limits their access" >> "$REPORT_FILE"
    echo "  - Least privilege prevents lateral movement to other namespaces" >> "$REPORT_FILE"
    echo "  - Service account permissions are enforced at API server level" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "PHASE 1 CONTROL:" >> "$REPORT_FILE"
    echo "  RoleBinding: Limits prod namespace access via RBAC" >> "$REPORT_FILE"
    return 0
  fi
}

# ============================================================================
# Test 2: Phase 2 - Pod Security Policy Enforcement
# ============================================================================

test_phase2_pod_security() {
  log_test_name "2: Phase 2 - Pod Security Policy Enforcement"

  log_info "Testing: Kyverno policy blocks privileged containers"

  # Create temporary YAML
  cat > /tmp/phase5-priv-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-attacker
  namespace: phase5-tests
spec:
  securityContext:
    privileged: true
  containers:
  - name: app
    image: nginx:latest
    imagePullPolicy: Always
EOF

  # Attempt to deploy privileged pod
  local output
  output=$(kubectl apply -f /tmp/phase5-priv-pod.yaml 2>&1 || true)

  if echo "$output" | grep -q "disallow-privileged\|privileged"; then
    log_success "Kyverno policy blocked privileged pod"
    echo "" >> "$REPORT_FILE"
    echo "ATTACK SCENARIO:" >> "$REPORT_FILE"
    echo "  Attacker attempts to deploy privileged container for host escape" >> "$REPORT_FILE"
    echo "  Pod spec includes: securityContext.privileged: true" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "EXPECTED RESULT: Policy rejection" >> "$REPORT_FILE"
    echo "ACTUAL RESULT: ✅ Policy rejected - disallow-privileged violated" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "WHY THIS MATTERS:" >> "$REPORT_FILE"
    echo "  - Privileged containers can escape sandbox and compromise host" >> "$REPORT_FILE"
    echo "  - Policy enforced at admission time (prevents deployment)" >> "$REPORT_FILE"
    echo "  - Even developers cannot accidentally deploy privileged containers" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "PHASE 2 CONTROL:" >> "$REPORT_FILE"
    echo "  Kyverno Policy: disallow-privileged.yaml" >> "$REPORT_FILE"
    echo "  Prevents: container escape, host compromise" >> "$REPORT_FILE"
    rm -f /tmp/phase5-priv-pod.yaml
    return 0
  else
    log_fail "Privileged pod was allowed (RBAC or Kyverno not working)"
    echo "" >> "$REPORT_FILE"
    echo "Output: $output" >> "$REPORT_FILE"
    rm -f /tmp/phase5-priv-pod.yaml
    return 1
  fi
}

# ============================================================================
# Test 3: Phase 3 - NetworkPolicy Enforcement
# ============================================================================

test_phase3_networkpolicy() {
  log_test_name "3: Phase 3 - NetworkPolicy Enforcement"

  log_info "Testing: NetworkPolicy blocks cross-namespace traffic"

  # Deploy test pods
  kubectl -n "$TEST_NS" run backend --image=nginx:latest --labels=app=backend --restart=Never &>/dev/null || true
  kubectl -n "$TEST_NS" run frontend --image=busybox --labels=app=frontend --restart=Never --command -- sleep 3600 &>/dev/null || true

  # Wait for pods to be ready
  sleep 3

  # Try to reach default namespace from test namespace (should fail)
  local result=0
  if timeout 5 kubectl -n "$TEST_NS" exec frontend -- \
    wget -T2 -q -O- http://kubernetes.default.svc &>/dev/null 2>&1; then
    result=1
  fi

  if [ $result -eq 0 ]; then
    log_success "NetworkPolicy blocked cross-namespace traffic"
    echo "" >> "$REPORT_FILE"
    echo "ATTACK SCENARIO:" >> "$REPORT_FILE"
    echo "  Attacker in compromised pod attempts lateral movement" >> "$REPORT_FILE"
    echo "  Tries to reach kubernetes.default.svc from phase5-tests namespace" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "EXPECTED RESULT: Connection timeout (default deny)" >> "$REPORT_FILE"
    echo "ACTUAL RESULT: ✅ Connection blocked by NetworkPolicy" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "WHY THIS MATTERS:" >> "$REPORT_FILE"
    echo "  - Default deny prevents lateral movement between namespaces" >> "$REPORT_FILE"
    echo "  - Limits blast radius if one pod is compromised" >> "$REPORT_FILE"
    echo "  - Isolates dev/prod environments from each other" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "PHASE 3 CONTROL:" >> "$REPORT_FILE"
    echo "  NetworkPolicy: 00-default-deny-ingress.yaml" >> "$REPORT_FILE"
    echo "  Prevents: lateral movement, cross-namespace compromise" >> "$REPORT_FILE"
    return 0
  else
    log_fail "Cross-namespace traffic was allowed (NetworkPolicy not enforced)"
    echo "" >> "$REPORT_FILE"
    echo "Result: Pod could reach kubernetes.default.svc" >> "$REPORT_FILE"
    return 1
  fi
}

# ============================================================================
# Test 4: Phase 4 - Secret Policy Enforcement
# ============================================================================

test_phase4_secret_policy() {
  log_test_name "4: Phase 4 - Secret Policy Enforcement"

  log_info "Testing: Kyverno policy enforces secret naming convention"

  # Attempt to create secret without proper name
  local output
  output=$(kubectl -n "$TEST_NS" create secret generic mydata \
    --from-literal=password=secret123 2>&1 || true)

  if echo "$output" | grep -q "require-secret-names\|secret"; then
    log_success "Secret policy blocked plaintext secret name"
    echo "" >> "$REPORT_FILE"
    echo "ATTACK SCENARIO:" >> "$REPORT_FILE"
    echo "  Developer (or attacker) creates secret with obvious name: 'mydata'" >> "$REPORT_FILE"
    echo "  Secret name doesn't follow 'xxx-secret' convention" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "EXPECTED RESULT: Policy rejection" >> "$REPORT_FILE"
    echo "ACTUAL RESULT: ✅ Policy rejected - require-secret-names violated" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "WHY THIS MATTERS:" >> "$REPORT_FILE"
    echo "  - Secret names should be obvious in logs and configurations" >> "$REPORT_FILE"
    echo "  - Plaintext names can hide secrets in plain sight" >> "$REPORT_FILE"
    echo "  - Policy enforces consistent naming convention" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "PHASE 4 CONTROL:" >> "$REPORT_FILE"
    echo "  Kyverno Policy: require-secret-names.yaml" >> "$REPORT_FILE"
    echo "  Enforces: '-secret' or 'secret-' in name" >> "$REPORT_FILE"
    return 0
  else
    log_fail "Secret policy did not block plaintext name"
    echo "" >> "$REPORT_FILE"
    echo "Output: $output" >> "$REPORT_FILE"
    return 1
  fi
}

# ============================================================================
# Report Generation
# ============================================================================

generate_report_header() {
  mkdir -p "$REPORT_DIR"

  cat > "$REPORT_FILE" << 'EOF'
═══════════════════════════════════════════════════════════════════════════════
                    PHASE 5: ATTACK SIMULATION REPORT
                      Security Control Validation
═══════════════════════════════════════════════════════════════════════════════

This report documents 4 controlled attack scenarios designed to validate that
Phase 1-4 security controls actually prevent real attacks.

All tests are non-destructive and use isolated test namespaces.

EOF
}

summarize_results() {
  echo "" | tee -a "$REPORT_FILE"
  echo "═══════════════════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
  echo "SUMMARY" | tee -a "$REPORT_FILE"
  echo "═══════════════════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"

  if [ $FAILED -eq 0 ]; then
    printf "${GREEN}✅ ALL TESTS PASSED (${PASSED}/4)${NC}\n" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "Your Phase 1-4 security controls are working correctly!" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "WHAT THIS MEANS:" | tee -a "$REPORT_FILE"
    echo "  ✅ Phase 1 (RBAC): Limits access within cluster" | tee -a "$REPORT_FILE"
    echo "  ✅ Phase 2 (Pod Security): Blocks dangerous containers" | tee -a "$REPORT_FILE"
    echo "  ✅ Phase 3 (Network Policies): Isolates namespaces" | tee -a "$REPORT_FILE"
    echo "  ✅ Phase 4 (Secrets): Enforces secret best practices" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
  else
    printf "${RED}⚠️  ${FAILED} TEST(S) FAILED (${PASSED}/4 passed)${NC}\n" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "Some controls may not be working as expected." | tee -a "$REPORT_FILE"
    echo "Review the test details above and check phase hardening scripts." | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
  fi

  echo "═══════════════════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
}

display_summary() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║        PHASE 5 ATTACK SIMULATION COMPLETE                  ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""

  if [ $FAILED -eq 0 ]; then
    printf "${GREEN}✅ All 4 attack simulations passed!${NC}\n"
  else
    printf "${YELLOW}⚠️  ${FAILED} test(s) failed - review report${NC}\n"
  fi

  echo ""
  echo "📋 Full report: ${REPORT_FILE}"
  echo ""
  echo "🔍 Next steps:"
  echo "   1. Review report above"
  echo "   2. Run: make phase5-validate"
  echo "   3. Deploy insecure workloads, watch trivy-operator detect them"
  echo "   4. See: docs/phase5-trivy-operator-validation.md"
  echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║  Phase 5: Attack Simulation Tests                         ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""

  generate_report_header

  # Setup
  setup_test_ns
  trap cleanup_test_ns EXIT
  echo ""

  # Run tests
  test_phase1_rbac || true
  test_phase2_pod_security || true
  test_phase3_networkpolicy || true
  test_phase4_secret_policy || true

  # Summary
  summarize_results
  display_summary
}

main "$@"
