#!/usr/bin/env bash
# Phase 5: Trivy-Operator Query - Display findings from continuous scanning
#
# Queries trivy-operator CRDs and displays findings in a readable format.
# Shows:
# - Vulnerability reports (image CVEs)
# - Configuration audit reports (CIS benchmarks, security best practices)
# - Comparison with kube-bench/kubescape point-in-time tools
#
# Output: Formatted findings to console
# Time: ~2 minutes

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

OPERATOR_NS="trivy-system"

# Color codes
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
  printf "${CYAN}[info]${NC} %s\n" "$1"
}

log_success() {
  printf "${GREEN}✅${NC} %s\n" "$1"
}

log_error() {
  printf "${RED}❌ [ERROR]${NC} %s\n" "$1"
}

log_section() {
  printf "\n${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
  printf "${BLUE}%s${NC}\n" "$1"
  printf "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}

check_operator_running() {
  if ! kubectl get namespace "${OPERATOR_NS}" &>/dev/null; then
    log_error "trivy-system namespace not found"
    echo "Install with: make phase5-trivy-operator-install"
    exit 1
  fi

  if ! kubectl get pods -n "${OPERATOR_NS}" -l app.kubernetes.io/name=trivy-operator &>/dev/null; then
    log_error "trivy-operator pod not found"
    echo "Operator may still be starting. Check status:"
    echo "  kubectl get pods -n ${OPERATOR_NS}"
    exit 1
  fi

  log_success "trivy-operator is running"
}

wait_for_initial_scans() {
  log_info "Waiting for initial vulnerability scans to complete..."

  local attempts=0
  local max_attempts=30

  while [ $attempts -lt $max_attempts ]; do
    local vr_count
    vr_count=$(kubectl get vulnerabilityreports -A 2>/dev/null | wc -l)

    if [ "$vr_count" -gt 1 ]; then
      log_success "Found vulnerability reports (${vr_count} total including header)"
      return 0
    fi

    echo "  Waiting... (${attempts}/${max_attempts})"
    sleep 10
    attempts=$((attempts + 1))
  done

  log_info "No vulnerability reports found yet (operator may still be scanning)"
  log_info "This is normal on first run - scans take 1-5 minutes"
  return 0
}

show_vulnerability_reports() {
  log_section "VULNERABILITY REPORTS (Image CVEs)"

  local vr_count
  vr_count=$(kubectl get vulnerabilityreports -A 2>/dev/null | wc -l)

  if [ "$vr_count" -le 1 ]; then
    log_info "No vulnerability reports yet (still scanning or no vulnerable images)"
    return 0
  fi

  echo "Summary across all namespaces:"
  echo ""
  kubectl get vulnerabilityreports -A \
    --sort-by='.report.summary.criticalCount' \
    -o custom-columns=\
NAMESPACE:.metadata.namespace,\
RESOURCE:.metadata.name,\
CRITICAL:.report.summary.criticalCount,\
HIGH:.report.summary.highCount,\
MEDIUM:.report.summary.mediumCount,\
LOW:.report.summary.lowCount 2>/dev/null || true

  echo ""
  echo "📝 To see detailed CVEs:"
  echo "   kubectl get vulnerabilityreports -n <namespace> -o yaml"
  echo "   kubectl describe vulnerabilityreport -n <namespace> <name>"
}

show_config_audit_reports() {
  log_section "CONFIGURATION AUDIT REPORTS (CIS Benchmarks & Best Practices)"

  local ca_count
  ca_count=$(kubectl get configauditreports -A 2>/dev/null | wc -l)

  if [ "$ca_count" -le 1 ]; then
    log_info "No configuration audit reports yet (still scanning)"
    return 0
  fi

  echo "Summary across all namespaces:"
  echo ""
  kubectl get configauditreports -A \
    --sort-by='.report.summary.criticalCount' \
    -o custom-columns=\
NAMESPACE:.metadata.namespace,\
RESOURCE:.metadata.name,\
CRITICAL:.report.summary.criticalCount,\
HIGH:.report.summary.highCount,\
MEDIUM:.report.summary.mediumCount,\
LOW:.report.summary.lowCount 2>/dev/null || true

  echo ""
  echo "📝 To see what failed:"
  echo "   kubectl get configauditreports -n <namespace> -o yaml"
  echo "   kubectl describe configauditreport -n <namespace> <name>"
}

show_secret_reports() {
  log_section "SECRET EXPOSURE REPORTS"

  local sr_count
  sr_count=$(kubectl get secretreports -A 2>/dev/null | wc -l)

  if [ "$sr_count" -le 1 ]; then
    log_info "No secret exposure reports (no secrets detected)"
    return 0
  fi

  echo "Summary across all namespaces:"
  echo ""
  kubectl get secretreports -A 2>/dev/null || true

  echo ""
  echo "📝 To investigate:"
  echo "   kubectl describe secretreport -n <namespace> <name>"
}

show_rbac_reports() {
  log_section "RBAC ASSESSMENT REPORTS"

  local rbac_count
  rbac_count=$(kubectl get rbacassessmentreports -A 2>/dev/null | wc -l)

  if [ "$rbac_count" -le 1 ]; then
    log_info "No RBAC assessment reports yet"
    return 0
  fi

  echo "Summary across all namespaces:"
  echo ""
  kubectl get rbacassessmentreports -A 2>/dev/null || true
}

show_tool_comparison() {
  log_section "TOOL COMPARISON: Point-in-Time vs Continuous"

  cat << 'EOF'
┌─────────────────────────────────────────────────────────────────────────────┐
│ ASPECT              │ kube-bench      │ kubescape       │ trivy-operator      │
├─────────────────────────────────────────────────────────────────────────────┤
│ What it scans       │ CIS config      │ Multi-framework │ Everything          │
│ Configuration       │ YES             │ YES             │ YES (+ more)        │
│ Image vulns (CVEs)  │ NO              │ NO              │ YES                 │
│ Secrets exposure    │ NO              │ NO              │ YES                 │
│ RBAC analysis       │ NO              │ YES             │ YES                 │
│ Timing              │ Point-in-time   │ Point-in-time   │ Continuous          │
│ Trigger             │ Manual run      │ Manual run      │ Auto on changes     │
│ Kubernetes-native   │ NO (CLI)        │ NO (CLI)        │ YES (CRDs)          │
│ Best for            │ CIS audits      │ Multi-framework │ Ongoing monitoring  │
└─────────────────────────────────────────────────────────────────────────────┘

KEY INSIGHTS:

1. KUBE-BENCH (Point-in-time):
   ✓ Precise CIS Benchmark checks
   ✓ Good for compliance audits
   ✗ Must manually re-run to detect changes
   ✗ Only checks configuration, not container images

2. KUBESCAPE (Point-in-time):
   ✓ Multiple frameworks (NSA, MITRE, CIS, SOC2)
   ✓ Shows threat model context (MITRE tactics)
   ✓ Better remediation guidance
   ✗ Still point-in-time only
   ✗ Limited image scanning

3. TRIVY-OPERATOR (Continuous):
   ✓ Automatic scanning on workload changes
   ✓ Detects image vulnerabilities (CVEs)
   ✓ Kubernetes-native (queryable with kubectl)
   ✓ Includes CIS checks from kube-bench
   ✓ Includes RBAC & secret detection
   ✓ Persistent results as Kubernetes CRDs
   ✓ Best for production monitoring

RECOMMENDATION:
━━━━━━━━━━━━━
Use kube-bench/kubescape to LEARN what to look for.
Use trivy-operator to MONITOR your cluster.
Trivy-operator supersedes the point-in-time tools for ongoing operations.
EOF
}

show_cis_mapping() {
  log_section "HOW FINDINGS MAP TO PHASES 1-4"

  cat << 'EOF'
┌────────────────────────────────────────────────────────────────────────────┐
│ FINDING TYPE                    │ PHASE │ CONTROL                          │
├────────────────────────────────────────────────────────────────────────────┤
│ No RBAC configured              │ Phase 1 │ RoleBinding with least privilege    │
│ Unrestricted API access         │ Phase 1 │ ServiceAccount permissions          │
│ No namespace isolation          │ Phase 1 │ Namespaces + RBAC                  │
├────────────────────────────────────────────────────────────────────────────┤
│ Privileged containers allowed   │ Phase 2 │ Kyverno disallow-privileged policy  │
│ Running as root                 │ Phase 2 │ runAsNonRoot security context      │
│ Dangerous capabilities enabled  │ Phase 2 │ Kyverno drop-net-raw-capability    │
├────────────────────────────────────────────────────────────────────────────┤
│ Cross-namespace traffic allowed │ Phase 3 │ NetworkPolicy default deny + allows│
│ No ingress/egress controls      │ Phase 3 │ Default deny + explicit allows     │
├────────────────────────────────────────────────────────────────────────────┤
│ Secrets in environment vars     │ Phase 4 │ Kyverno disallow-env-secrets       │
│ Secrets not encrypted at rest   │ Phase 4 │ etcd encryption enabled            │
│ CVEs in container images        │ Phase 4 │ Regular Trivy scanning             │
└────────────────────────────────────────────────────────────────────────────┘
EOF
}

show_next_steps() {
  log_section "NEXT STEPS"

  cat << 'EOF'
1. UNDERSTAND THE FINDINGS:
   Read: docs/phase5-assessment-guide.md
   Link findings to Phase 1-4 controls: docs/phase5-control-mapping.md

2. REMEDIATE FINDINGS (if any):
   Each report shows which resources failed and why
   Fix the resource, trivy-operator will re-scan automatically

3. HANDS-ON VALIDATION:
   See how trivy-operator detects real problems
   Run: make phase5-validate
   Follow: docs/phase5-trivy-operator-validation.md

4. RUN ATTACK SIMULATIONS:
   Verify Phase 1-4 controls actually prevent attacks
   Run: make phase5-simulate

5. PRODUCTION USAGE:
   trivy-operator can monitor your cluster continuously
   Export results to monitoring/alerting systems
   Set SLAs for fixing CRITICAL/HIGH findings
EOF
}

# ============================================================================
# Main
# ============================================================================

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║  Phase 5: Trivy-Operator Query Results                    ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""

  check_operator_running
  echo ""

  wait_for_initial_scans
  echo ""

  show_vulnerability_reports
  show_config_audit_reports
  show_secret_reports
  show_rbac_reports

  show_tool_comparison
  show_cis_mapping
  show_next_steps
}

main "$@"
