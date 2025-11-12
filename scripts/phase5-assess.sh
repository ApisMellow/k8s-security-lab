#!/usr/bin/env bash
# Phase 5: Assessment - Run kube-bench and kubescape for security assessment
#
# This script performs a point-in-time security assessment using:
# - kube-bench: CIS Kubernetes Benchmark compliance checking
# - kubescape: Multi-framework posture assessment
#
# Output: Timestamped reports in reports/phase5-assessment/
# Time: ~8 minutes

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR="${PROJECT_ROOT}/reports/phase5-assessment/${TIMESTAMP}"
LOG_FILE="${REPORT_DIR}/assessment.log"

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
  printf "${CYAN}[info]${NC} %s\n" "$1" | tee -a "$LOG_FILE"
}

log_success() {
  printf "${GREEN}✅${NC} %s\n" "$1" | tee -a "$LOG_FILE"
}

log_error() {
  printf "${RED}❌ [ERROR]${NC} %s\n" "$1" | tee -a "$LOG_FILE"
}

log_warn() {
  printf "${YELLOW}⚠️${NC}  %s\n" "$1" | tee -a "$LOG_FILE"
}

check_cluster_running() {
  if ! kubectl cluster-info &>/dev/null; then
    log_error "Cluster not running"
    echo ""
    echo "To start cluster, run one of:"
    echo "  make phase4           # Full 4-phase cluster"
    echo "  make phase4-up        # Just create cluster"
    exit 1
  fi
  log_success "Cluster is running"
}

check_docker_running() {
  if ! docker info &>/dev/null; then
    log_error "Docker is not running"
    echo "Please start Docker Desktop"
    exit 1
  fi
  log_success "Docker is running"
}

check_kubescape_available() {
  if ! command -v kubescape &>/dev/null; then
    log_error "kubescape not found in PATH"
    echo "Ensure you are in devbox shell: devbox shell"
    exit 1
  fi
  log_success "kubescape is available"
}

# ============================================================================
# Assessment Functions
# ============================================================================

run_kube_bench() {
  log_info "Running kube-bench (CIS Kubernetes Benchmark v1.23)..."

  # Run kube-bench in a temp namespace without strict policies
  kubectl create namespace phase5-kube-bench --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true

  # Run kube-bench pod without interactive TTY
  kubectl run kube-bench \
    --image=aquasec/kube-bench:latest \
    --restart=Never \
    -n phase5-kube-bench \
    -- run --json 2>"${REPORT_DIR}/kube-bench.log" > /dev/null || true

  # Wait for pod to complete (or timeout)
  kubectl wait --for=condition=Ready pod/kube-bench -n phase5-kube-bench --timeout=120s 2>/dev/null || true

  # Get logs from the pod (contains the JSON output)
  # Even if pod failed, logs might still be available
  sleep 2  # Give pod time to finish writing logs
  kubectl logs kube-bench -n phase5-kube-bench > "${REPORT_DIR}/kube-bench-results.json" 2>/dev/null || true

  # Clean up temp namespace AFTER getting logs
  kubectl delete namespace phase5-kube-bench --ignore-not-found=true 2>/dev/null || true

  # Parse results
  local failed_count=0

  if [ -f "${REPORT_DIR}/kube-bench-results.json" ] && [ -s "${REPORT_DIR}/kube-bench-results.json" ]; then
    failed_count=$(jq '[.Controls[] | .tests[] | .results[] | select(.status=="FAIL")] | length' "${REPORT_DIR}/kube-bench-results.json" 2>/dev/null || echo "0")

    # Display summary in terminal
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "kube-bench: CIS Kubernetes Benchmark Results"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    jq -r '.Controls[] | "[\(.id)] \(.text)"' "${REPORT_DIR}/kube-bench-results.json"
    echo ""
    echo "Failed Checks: ${failed_count}"
    echo "Sample failures (first 10):"
    jq -r '.Controls[] | .tests[] | .results[] | select(.status=="FAIL") | "  • \(.test_number): \(.test_desc)"' "${REPORT_DIR}/kube-bench-results.json" | head -10
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
  fi

  log_success "kube-bench: ${failed_count} failed checks found"

  echo "kube-bench Results" >> "$LOG_FILE"
  echo "  Failed: ${failed_count}" >> "$LOG_FILE"
}

run_kubescape() {
  log_info "Running kubescape (Multi-framework posture assessment)..."

  if ! kubescape scan framework NSA,cis-v1.10.0 \
    --format json \
    --output "${REPORT_DIR}/kubescape-results.json" \
    &>"${REPORT_DIR}/kubescape.log"; then
    log_warn "kubescape completed with warnings (expected)"
  fi

  # Parse results
  local score=0
  local passed=0
  local failed=0
  local skipped=0

  if [ -f "${REPORT_DIR}/kubescape-results.json" ] && [ -s "${REPORT_DIR}/kubescape-results.json" ]; then
    score=$(jq '.summaryDetails.complianceScore // 0' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null | xargs printf "%.0f" || echo "0")
    passed=$(jq '[.summaryDetails.controls[]? | select(.status=="passed")] | length' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null || echo "0")
    failed=$(jq '[.summaryDetails.controls[]? | select(.status=="failed")] | length' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null || echo "0")
    skipped=$(jq '[.summaryDetails.controls[]? | select(.status=="skipped")] | length' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null || echo "0")

    # Display summary in terminal
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "kubescape: Multi-Framework Posture Assessment"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Overall Compliance Score: ${score}%"
    echo ""
    echo "Control Status:"
    echo "  ✅ Passed: ${passed}"
    echo "  ❌ Failed: ${failed}"
    echo "  ⏭️  Skipped: ${skipped}"
    echo ""
    if [ "${failed}" -gt 0 ]; then
      echo "Sample Failed Controls (first 10):"
      jq -r '.summaryDetails.controls[]? | select(.status=="failed") | "  [\(.controlID)] \(.name)"' "${REPORT_DIR}/kubescape-results.json" | head -10
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
  fi

  log_success "kubescape: ${score}% compliance (${passed} passed, ${failed} failed)"

  echo "kubescape Results" >> "$LOG_FILE"
  echo "  Compliance Score: ${score}%" >> "$LOG_FILE"
  echo "  Passed: ${passed}" >> "$LOG_FILE"
  echo "  Failed: ${failed}" >> "$LOG_FILE"
}

generate_html_report() {
  log_info "Generating HTML report..."

  # Build kube-bench failures table rows
  local kb_table_rows=""
  if [ -f "${REPORT_DIR}/kube-bench-results.json" ] && [ -s "${REPORT_DIR}/kube-bench-results.json" ]; then
    kb_table_rows=$(jq -r '.Controls[] | .tests[] | .results[] | select(.status=="FAIL") | "<tr><td style=\"border: 1px solid #d1d5db; padding: 8px; font-family: monospace; width: 10%;\">\(.test_number)</td><td style=\"border: 1px solid #d1d5db; padding: 8px;\">\(.test_desc)</td></tr>"' "${REPORT_DIR}/kube-bench-results.json" 2>/dev/null | head -30)
  fi

  # Build kubescape failures table rows
  local ks_table_rows=""
  if [ -f "${REPORT_DIR}/kubescape-results.json" ] && [ -s "${REPORT_DIR}/kubescape-results.json" ]; then
    ks_table_rows=$(jq -r '.summaryDetails.controls[]? | select(.status=="failed") | "<tr><td style=\"border: 1px solid #d1d5db; padding: 8px; font-family: monospace; width: 10%;\">\(.controlID)</td><td style=\"border: 1px solid #d1d5db; padding: 8px;\">\(.name)</td></tr>"' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null | head -30)
  fi

  cat > "${REPORT_DIR}/assessment-report.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>Phase 5 Security Assessment Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .header { background: #1e3a8a; color: white; padding: 20px; border-radius: 5px; }
    .section { background: white; margin: 20px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .section h2 { border-bottom: 2px solid #1e3a8a; padding-bottom: 10px; }
    .tool-box { background: #f9fafb; padding: 15px; margin: 10px 0; border-left: 4px solid #1e3a8a; }
    .success { color: #059669; }
    .warning { color: #d97706; }
    .error { color: #dc2626; }
    pre { background: #f3f4f6; padding: 10px; border-radius: 3px; overflow-x: auto; }
    .next-steps { background: #ecfdf5; border: 1px solid #a7f3d0; padding: 15px; border-radius: 5px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Phase 5: Security Assessment Report</h1>
    <p>Point-in-time security compliance and posture evaluation</p>
  </div>

  <div class="section">
    <h2>Assessment Overview</h2>
    <p>This report evaluates your Kubernetes cluster security posture using industry-standard tools:</p>
    <ul>
      <li><strong>kube-bench</strong>: CIS Kubernetes Benchmark compliance (100+ checks)</li>
      <li><strong>kubescape</strong>: Multi-framework posture assessment (NSA-CISA, MITRE, CIS, SOC2)</li>
    </ul>
  </div>

  <div class="section">
    <h2>kube-bench Results (CIS Kubernetes Benchmark)</h2>
    <p>The Center for Internet Security (CIS) Benchmark defines security best practices for Kubernetes.</p>
    <div class="tool-box">
      <p><strong>What PASS means:</strong> Configuration complies with CIS recommendation</p>
      <p><strong>What FAIL means:</strong> Configuration violates CIS recommendation</p>
      <p><strong>What WARN means:</strong> Check not applicable or warning-level issue</p>
      <h3>Failed Checks</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <tr style="background: #f3f4f6;">
          <th style="border: 1px solid #d1d5db; padding: 10px; text-align: left; width: 10%;">Test ID</th>
          <th style="border: 1px solid #d1d5db; padding: 10px; text-align: left;">Description</th>
        </tr>
        KB_TABLE_ROWS
      </table>
    </div>
  </div>

  <div class="section">
    <h2>kubescape Results (Multi-Framework Posture)</h2>
    <p>Kubescape evaluates compliance against multiple security frameworks:</p>
    <ul>
      <li>CIS Kubernetes Benchmark</li>
      <li>NSA-CISA Hardening Guidance</li>
      <li>MITRE ATT&CK Framework</li>
      <li>SOC 2 Compliance</li>
    </ul>
    <div class="tool-box">
      <p><strong>Score meaning:</strong> Percentage of controls passing across all frameworks</p>
      <p><strong>Low score indicates:</strong> Focus remediation on failed controls</p>
      <h3>Failed Controls</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <tr style="background: #f3f4f6;">
          <th style="border: 1px solid #d1d5db; padding: 10px; text-align: left; width: 10%;">Control ID</th>
          <th style="border: 1px solid #d1d5db; padding: 10px; text-align: left;">Control Name</th>
        </tr>
        KS_TABLE_ROWS
      </table>
    </div>
  </div>

  <div class="section">
    <h2>How Phases 1-4 Address These Findings</h2>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="background: #f3f4f6;">
        <th style="border: 1px solid #d1d5db; padding: 10px;">Finding Type</th>
        <th style="border: 1px solid #d1d5db; padding: 10px;">Phase</th>
        <th style="border: 1px solid #d1d5db; padding: 10px;">Control</th>
      </tr>
      <tr>
        <td style="border: 1px solid #d1d5db; padding: 10px;">No RBAC restrictions</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Phase 1</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Role-based access control with RoleBindings</td>
      </tr>
      <tr>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Privileged containers allowed</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Phase 2</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Kyverno disallow-privileged policy</td>
      </tr>
      <tr>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Cross-namespace traffic not restricted</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Phase 3</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">NetworkPolicy default deny + explicit allows</td>
      </tr>
      <tr>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Secrets not encrypted at rest</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">Phase 4</td>
        <td style="border: 1px solid #d1d5db; padding: 10px;">etcd encryption enabled at cluster creation</td>
      </tr>
    </table>
  </div>

  <div class="section next-steps">
    <h2>Next Steps</h2>
    <ol>
      <li><strong>Review findings:</strong> Are the results what you expected?</li>
      <li><strong>Understand controls:</strong> Read docs/phase5-assessment-guide.md</li>
      <li><strong>Install continuous monitoring:</strong> <code>make phase5-trivy-operator-install</code></li>
      <li><strong>Compare tools:</strong> <code>make phase5-trivy-operator-query</code></li>
      <li><strong>Run attack simulations:</strong> <code>make phase5-simulate</code></li>
    </ol>
  </div>

  <div class="section">
    <h2>Files Generated</h2>
    <pre>reports/phase5-assessment/TIMESTAMP/
  ├── assessment-report.html          (This file)
  ├── kube-bench-results.json         (CIS benchmark raw results)
  ├── kubescape-results.json          (Posture assessment raw results)
  ├── kube-bench.log                  (Kube-bench execution log)
  ├── kubescape.log                   (Kubescape execution log)
  └── assessment.log                  (Combined log)</pre>
  </div>


</body>
</html>
EOF

  # Substitute table rows into the HTML using a temp file
  local temp_html="${REPORT_DIR}/assessment-report.html.tmp"
  cp "${REPORT_DIR}/assessment-report.html" "$temp_html"

  # Replace placeholders with table rows
  awk -v kb_rows="$kb_table_rows" '{gsub(/KB_TABLE_ROWS/, kb_rows); print}' "$temp_html" > "${REPORT_DIR}/assessment-report.html"
  cp "${REPORT_DIR}/assessment-report.html" "$temp_html"
  awk -v ks_rows="$ks_table_rows" '{gsub(/KS_TABLE_ROWS/, ks_rows); print}' "$temp_html" > "${REPORT_DIR}/assessment-report.html"

  rm -f "$temp_html"

  log_success "HTML report generated"
}

display_summary() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║        PHASE 5 ASSESSMENT COMPLETE                         ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""
  echo "📊 Assessment Reports:"
  echo "   HTML:      open ${REPORT_DIR}/assessment-report.html"
  echo "   Raw JSON:  ${REPORT_DIR}/kube-bench-results.json"
  echo "   Raw JSON:  ${REPORT_DIR}/kubescape-results.json"
  echo "   Logs:      ${REPORT_DIR}/*.log"
  echo ""
  echo "📚 Learn More:"
  echo "   View guide: docs/phase5-assessment-guide.md"
  echo ""
  echo "🔄 Next Steps:"
  echo "   1. Review findings above"
  echo "   2. Run: make phase5-trivy-operator-install"
  echo "   3. Run: make phase5-trivy-operator-query"
  echo "   4. Compare point-in-time vs continuous scanning"
  echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║  Phase 5: Security Assessment (kube-bench + kubescape)    ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""

  # Create report directory
  mkdir -p "$REPORT_DIR"

  # Initialize log
  {
    echo "Phase 5 Security Assessment"
    echo "Timestamp: ${TIMESTAMP}"
    echo "Cluster: $(kubectl config current-context)"
    echo ""
  } > "$LOG_FILE"

  # Validate prerequisites
  log_info "Validating prerequisites..."
  check_cluster_running
  check_docker_running
  check_kubescape_available
  echo ""

  # Run assessments
  run_kube_bench
  echo ""
  run_kubescape
  echo ""

  # Generate report
  generate_html_report
  echo ""

  # Display summary
  display_summary
}

main "$@"
