#!/usr/bin/env bash
# Phase 5: Trivy-Operator Installation - Deploy continuous security scanning
#
# Installs Aqua Security's trivy-operator via Helm chart.
# trivy-operator continuously scans your cluster for:
# - Container image vulnerabilities (CVEs)
# - Configuration audit findings (CIS benchmarks)
# - Secret exposure detection
# - RBAC assessment
#
# Output: Operator running in trivy-system namespace
# Time: ~5 minutes

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

OPERATOR_NS="trivy-system"
HELM_RELEASE="trivy-operator"
HELM_REPO="aqua"
HELM_CHART="aqua/trivy-operator"
HELM_VERSION="0.31.0"

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
  printf "${CYAN}[info]${NC} %s\n" "$1"
}

log_success() {
  printf "${GREEN}✅${NC} %s\n" "$1"
}

log_error() {
  printf "${RED}❌ [ERROR]${NC} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}⚠️${NC}  %s\n" "$1"
}

check_helm_installed() {
  if ! command -v helm &>/dev/null; then
    log_error "Helm not found in PATH"
    echo "Ensure you are in devbox shell: devbox shell"
    exit 1
  fi
  log_success "Helm is available"
}

check_cluster_running() {
  if ! kubectl cluster-info &>/dev/null; then
    log_error "Cluster not running"
    echo "Run: make phase4"
    exit 1
  fi
  log_success "Cluster is running"
}

check_phases_complete() {
  # Check if Phase 2 is complete (Kyverno should be installed)
  if ! kubectl get ns kyverno &>/dev/null; then
    log_warn "Kyverno namespace not found"
    log_warn "Phase 2 may not be complete, but we can continue"
  fi

  # Check if Phase 4 is complete (test cluster should exist)
  if ! kubectl get nodes &>/dev/null 2>&1 | grep -q Ready; then
    log_warn "No ready nodes detected, but continuing..."
  fi
}

add_helm_repo() {
  log_info "Adding Aqua Security Helm repository..."

  if ! helm repo list | grep -q "^${HELM_REPO}"; then
    helm repo add "${HELM_REPO}" https://aquasecurity.github.io/helm-charts/
    log_success "Helm repo added"
  else
    log_success "Helm repo already added"
  fi

  log_info "Updating Helm repositories..."
  helm repo update "${HELM_REPO}"
  log_success "Helm repos updated"
}

create_namespace() {
  log_info "Creating trivy-system namespace..."

  if kubectl get namespace "${OPERATOR_NS}" &>/dev/null; then
    log_success "Namespace already exists"
  else
    kubectl create namespace "${OPERATOR_NS}"
    log_success "Namespace created"
  fi
}

deploy_operator() {
  log_info "Deploying trivy-operator via Helm..."

  if helm list -n "${OPERATOR_NS}" | grep -q "${HELM_RELEASE}"; then
    log_warn "trivy-operator already installed, upgrading..."
    helm upgrade "${HELM_RELEASE}" "${HELM_CHART}" \
      --namespace "${OPERATOR_NS}" \
      --version "${HELM_VERSION}" \
      --set="trivyOperator.scanJobsInNamespaces=default,dev,prod,kyverno" \
      --wait \
      --timeout 5m
  else
    log_info "Installing trivy-operator..."
    helm install "${HELM_RELEASE}" "${HELM_CHART}" \
      --namespace "${OPERATOR_NS}" \
      --create-namespace \
      --version "${HELM_VERSION}" \
      --set="trivyOperator.scanJobsInNamespaces=default,dev,prod,kyverno" \
      --wait \
      --timeout 5m
  fi

  log_success "trivy-operator deployed"
}

wait_for_operator() {
  log_info "Waiting for trivy-operator pod to be ready (timeout: 300s)..."

  if kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=trivy-operator \
    -n "${OPERATOR_NS}" \
    --timeout=300s 2>/dev/null; then
    log_success "trivy-operator pod is ready"
  else
    log_warn "Timeout waiting for pod, but deployment may be in progress"
    log_info "Check status with: kubectl get pods -n ${OPERATOR_NS}"
  fi
}

verify_installation() {
  log_info "Verifying trivy-operator installation..."

  # Check operator pod
  local operator_pods
  operator_pods=$(kubectl get pods -n "${OPERATOR_NS}" -l app.kubernetes.io/name=trivy-operator --no-headers 2>/dev/null | wc -l)

  if [ "$operator_pods" -gt 0 ]; then
    log_success "trivy-operator pod is running"
  else
    log_warn "No operator pods found yet, may still be starting"
  fi

  # Check for CRDs
  local crds
  crds=$(kubectl get crd | grep -c "aquasecurity.github.io" 2>/dev/null || echo "0")

  if [ "$crds" -gt 0 ]; then
    log_success "trivy-operator CRDs installed (${crds} found)"
  else
    log_warn "CRDs not yet visible, may still be installing"
  fi
}

display_next_steps() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║        TRIVY-OPERATOR INSTALLED                            ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""
  echo "✅ trivy-operator is now running in the ${OPERATOR_NS} namespace"
  echo ""
  echo "📊 VIEWING FINDINGS:"
  echo ""
  echo "Vulnerability Reports (image CVEs):"
  echo "  kubectl get vulnerabilityreports -A"
  echo "  kubectl describe vulnerabilityreport -n <ns> <report-name>"
  echo ""
  echo "Configuration Audit Reports (CIS Benchmarks, security best practices):"
  echo "  kubectl get configauditreports -A"
  echo "  kubectl describe configauditreport -n <ns> <report-name>"
  echo ""
  echo "Secret Detection Reports:"
  echo "  kubectl get secretreports -A"
  echo "  kubectl describe secretreport -n <ns> <report-name>"
  echo ""
  echo "RBAC Assessment Reports:"
  echo "  kubectl get rbacassessmentreports -A"
  echo ""
  echo "📝 EXAMPLE: View detailed vulnerability for a pod:"
  echo "  kubectl get vulnerabilityreports -n default -o wide"
  echo "  kubectl describe vulnerabilityreport -n default <pod-name>"
  echo ""
  echo "⏱️  Initial scan will take 1-5 minutes to complete."
  echo "   Operator will continuously scan as workloads are created/updated."
  echo ""
  echo "🔄 Next steps:"
  echo "  1. Wait 1-2 minutes for initial scans to complete"
  echo "  2. Run: make phase5-trivy-operator-query"
  echo "  3. Compare with point-in-time tools"
  echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║  Phase 5: Install Trivy-Operator (Continuous Scanning)    ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""

  log_info "Validating prerequisites..."
  check_helm_installed
  check_cluster_running
  check_phases_complete
  echo ""

  add_helm_repo
  echo ""

  create_namespace
  echo ""

  deploy_operator
  echo ""

  wait_for_operator
  echo ""

  verify_installation
  echo ""

  display_next_steps
}

main "$@"
