# Unified Makefile for Kubernetes Security Lab (After Phase 1 completed)
SHELL := /usr/bin/env bash

# ---------------------------- Config -----------------------------------------
KUBECTL        ?= kubectl
NS             ?= dev prod
POLICY_DIR     ?= policies/phase-2-baseline  # Phase 2 Kyverno baseline policies
NP_DIR         ?= network-policies           # Phase 3 NetworkPolicies
KYVERNO_NS     ?= kyverno

# Colors
YELLOW := \033[33m
GREEN  := \033[32m
CYAN   := \033[36m
RED    := \033[31m
NC     := \033[0m

define say
	@printf "$(CYAN)[make]$(NC) %s\n" $(1)
endef

.PHONY: help \
        phase1 phase1-up phase1-harden phase1-reset phase1-status \
        phase2 phase2-harden phase2-apply phase2-reset phase2-status phase2-diff phase2-lint \
        phase3 phase3-harden phase3-apply phase3-reset phase3-status phase3-test phase3-diff phase3-lint \
        phase4 phase4-up phase4-harden phase4-scan phase4-reset phase4-status phase4-down \
        phase5 phase5-assess phase5-trivy-operator-install phase5-trivy-operator-query phase5-simulate phase5-validate phase5-reset \
        status nuke-namespaces reclaim-disk cluster-down cluster-status _check-kubectl

# ---------------------------- Help -------------------------------------------
help:
	@echo "Targets:"
	@echo "  phase1            - Alias for phase1-harden (shortcut: create cluster + apply RBAC/namespaces + test)"
	@echo "  phase1-up         - Create k3d cluster with audit logging enabled"
	@echo "  phase1-harden     - Apply namespaces, RBAC, and run verification tests"
	@echo "  phase1-reset      - Run scripts/reset-phase1.sh (remove RBAC/namespaces, keep cluster)"
	@echo "  phase1-status     - Show cluster context and node status"
	@echo ""
	@echo "  phase2            - Alias for phase2-harden"
	@echo "  phase2-harden     - Run scripts/harden-phase2.sh (PSA + Kyverno baseline)"
	@echo "  phase2-apply      - kubectl apply Phase 2 policy yamls in '$(POLICY_DIR)/'"
	@echo "  phase2-reset      - Run scripts/reset-phase2.sh (remove Kyverno/PSA baseline)"
	@echo "  phase2-status     - Show Kyverno policies and Kyverno components"
	@echo "  phase2-diff       - kubectl diff on Phase 2 policy yamls"
	@echo "  phase2-lint       - yamllint for Phase 2 yamls (optional)"
	@echo ""
	@echo "  phase3            - Alias for phase3-harden"
	@echo "  phase3-harden     - Run scripts/harden-phase3.sh (default deny + allows)"
	@echo "  phase3-apply      - Apply baseline NetworkPolicies in '$(NP_DIR)/'"
	@echo "  phase3-reset      - Run scripts/reset-phase3.sh (remove NP baseline)"
	@echo "  phase3-status     - Show NetworkPolicies and pods in $(NS)"
	@echo "  phase3-test       - Quick demo connectivity check (dev namespace)"
	@echo "  phase3-diff       - kubectl diff for baseline NetworkPolicies"
	@echo "  phase3-lint       - yamllint for Phase 3 yamls (optional)"
	@echo ""
	@echo "  phase4            - Create NEW cluster + apply policies (⚠️ REQUIRES: make cluster-down first)"
	@echo "  phase4-up         - Create k3d cluster with secrets encryption + audit logging"
	@echo "  phase4-harden     - Apply Kyverno secret-hygiene policies (Phase 4)"
	@echo "  phase4-scan       - Run Trivy scans to verify security posture (manifests + cluster)"
	@echo "  phase4-reset      - Remove Phase 4 policies from cluster (repo untouched)"
	@echo "  phase4-status     - Show Phase 4 policy state (Kyverno secret policies)"
	@echo "  phase4-down       - Delete k3d cluster"
	@echo ""
	@echo "  phase5            - Full assessment + attack simulations (requires Phase 4)"
	@echo "  phase5-assess     - Run kube-bench + kubescape security assessment"
	@echo "  phase5-trivy-operator-install - Deploy continuous vulnerability scanning"
	@echo "  phase5-trivy-operator-query   - Display trivy-operator findings"
	@echo "  phase5-simulate   - Run attack simulation tests (validates Phase 1-4 controls)"
	@echo "  phase5-validate   - Hands-on validation: deploy insecure workloads, watch detection"
	@echo "  phase5-reset      - Clean up Phase 5 resources (trivy-system namespace, reports)"
	@echo ""
	@echo "  status            - Cluster high-level status (contexts, nodes, ns, pods)"
	@echo "  nuke-namespaces   - Delete common demo namespaces (config NS=...)"
	@echo "  reclaim-disk      - Docker prune images/volumes/builders (DANGEROUS)"
	@echo "  cluster-down      - Stop/delete k3d cluster"
	@echo "  cluster-status    - Show k3d cluster status"

# ---------------------------- Phase 1 ----------------------------------------
phase1: phase1-up phase1-harden

phase1-up: _check-kubectl
	$(call say,"Creating k3d cluster with audit logging enabled")
	@bash scripts/cluster-up-phase1-with-audit.sh

phase1-harden: _check-kubectl
	$(call say,"Applying Phase 1 RBAC and namespaces")
	@kubectl apply -f manifests/namespaces.yaml
	@kubectl apply -f manifests/rbac-dev-view.yaml
	@bash scripts/harden-phase1.sh

phase1-reset: _check-kubectl
	$(call say,"Removing Phase 1 resources via scripts/reset-phase1.sh")
	@bash scripts/reset-phase1.sh

phase1-status: _check-kubectl
	$(call say,"Phase 1 status")
	@kubectl config current-context
	@kubectl get nodes -o wide
	@kubectl get ns dev prod

# ---------------------------- Phase 2 ----------------------------------------
phase2: phase2-harden

phase2-harden: _check-kubectl
	$(call say,"Applying Phase 2 baseline via scripts/harden-phase2.sh")
	@bash scripts/harden-phase2.sh

phase2-apply: _check-kubectl
	$(call say,"Applying Phase 2 policies from $(POLICY_DIR) to the cluster")
	@set -euo pipefail; \
	test -d "$(POLICY_DIR)" || { printf "$(RED)Missing $(POLICY_DIR)/$(NC)\n"; exit 1; } ; \
	for f in $$(ls "$(POLICY_DIR)"/*.yaml 2>/dev/null); do \
		printf "$(YELLOW)==> %s$(NC)\n" $$f; \
		$(KUBECTL) apply -f $$f; \
	done
	@printf "$(GREEN)Phase 2 policies applied.$(NC)\n"

phase2-reset: _check-kubectl
	$(call say,"Removing Phase 2 baseline via scripts/reset-phase2.sh")
	@bash scripts/reset-phase2.sh

phase2-status: _check-kubectl
	$(call say,"Kyverno status and policies")
	@$(KUBECTL) -n $(KYVERNO_NS) get deploy,ds,po 2>/dev/null || true
	@echo "--- ClusterPolicies ---"
	@$(KUBECTL) get cpol 2>/dev/null || true
	@echo "--- Namespaced Policies ---"
	@$(KUBECTL) get pol -A 2>/dev/null || true

phase2-diff: _check-kubectl
	$(call say,"kubectl diff for Phase 2 policies")
	@set -euo pipefail; \
	for f in $$(ls "$(POLICY_DIR)"/*.yaml 2>/dev/null); do \
		printf "$(YELLOW)==> diff %s$(NC)\n" $$f; \
		$(KUBECTL) diff -f $$f || true; \
	done

phase2-lint:
	$(call say,"yamllint $(POLICY_DIR)")
	@command -v yamllint >/dev/null || { printf "$(YELLOW)yamllint not installed; skipping.$(NC)\n"; exit 0; }
	@yamllint -s $(POLICY_DIR)

# ---------------------------- Phase 3 ----------------------------------------
phase3: phase3-harden

phase3-harden: _check-kubectl
	$(call say,"Applying Phase 3 baseline via scripts/harden-phase3.sh")
	@bash scripts/harden-phase3.sh

phase3-apply: _check-kubectl
	$(call say,"Applying Phase 3 baseline policies to namespaces: $(NS)")
	@set -euo pipefail; \
	test -d "$(NP_DIR)" || { printf "$(RED)Missing $(NP_DIR)/$(NC)\n"; exit 1; } ; \
	for ns in $(NS); do \
		printf "$(YELLOW)==> ns: %s$(NC)\n" $$ns; \
		$(KUBECTL) get ns $$ns >/dev/null 2>&1 || $(KUBECTL) create ns $$ns; \
		for f in 00-default-deny-ingress.yaml 01-default-deny-egress.yaml \
		         10-allow-dns-egress.yaml 20-allow-same-namespace.yaml; do \
			$(KUBECTL) -n $$ns apply -f "$(NP_DIR)/$$f"; \
		done; \
	done
	@printf "$(GREEN)Phase 3 baseline applied.$(NC)\n"

phase3-reset: _check-kubectl
	$(call say,"Removing Phase 3 baseline via scripts/reset-phase3.sh")
	@bash scripts/reset-phase3.sh

phase3-status: _check-kubectl
	$(call say,"NetworkPolicy status for: $(NS)")
	@set -euo pipefail; \
	for ns in $(NS); do \
		printf "\n$(YELLOW)==> ns: %s$(NC)\n" $$ns; \
		$(KUBECTL) -n $$ns get netpol || true; \
		printf "$(CYAN)-- pods --$(NC)\n"; \
		$(KUBECTL) -n $$ns get pod -o wide || true; \
	done

phase3-diff: _check-kubectl
	$(call say,"kubectl diff for Phase 3 baseline policies")
	@set -euo pipefail; \
	for ns in $(NS); do \
		printf "\n$(YELLOW)==> diff ns: %s$(NC)\n" $$ns; \
		for f in 00-default-deny-ingress.yaml 01-default-deny-egress.yaml \
		         10-allow-dns-egress.yaml 20-allow-same-namespace.yaml; do \
			$(KUBECTL) -n $$ns diff -f "$(NP_DIR)/$$f" || true; \
		done; \
	done

phase3-test: _check-kubectl
	$(call say,"Quick connectivity check in 'dev'")
	@set -euo pipefail; \
	ns=dev; \
	$(KUBECTL) -n $$ns run backend --image=nginx --labels app=backend -- sh -lc 'nginx -g "daemon off;"' || true; \
	$(KUBECTL) -n $$ns run frontend --image=busybox --labels app=frontend --restart=Never -- sh -lc 'sleep 300' || true; \
	$(KUBECTL) -n $$ns wait --for=condition=Ready pod/frontend --timeout=90s || true; \
	printf "$(CYAN)-- Expect FAIL before app-to-app allow --$(NC)\n"; \
	$(KUBECTL) -n $$ns exec frontend -- sh -lc 'wget -S -O- http://backend:8080 2>&1 | head -n2' || true; \
	printf "$(CYAN)-- Apply 30-allow-app-to-app.yaml to allow --$(NC)\n"; \
	$(KUBECTL) -n $$ns delete pod frontend backend --ignore-not-found=true >/dev/null 2>&1 || true; \
	printf "$(GREEN)phase3-test completed.$(NC)\n"

phase3-lint:
	$(call say,"yamllint $(NP_DIR)")
	@command -v yamllint >/dev/null || { printf "$(YELLOW)yamllint not installed; skipping.$(NC)\n"; exit 0; }
	@yamllint -s $(NP_DIR)

# ---- Phase 4: Secrets Hygiene & Encryption  -----------------------
K3D_NAME    ?= phase4

phase4: phase4-up phase2-harden phase4-harden

phase4-up: _check-kubectl
	$(call say,"Bringing up k3d cluster '$(K3D_NAME)' with secrets encryption + audit")
	@bash scripts/cluster-up-phase4.sh "$(K3D_NAME)"

phase4-harden: _check-kubectl
	$(call say,"Applying Phase 4 Kyverno policies (secret hygiene)")
	@bash scripts/harden-phase4.sh
	@echo ""
	@echo "✅ Phase 4 Hardening Complete!"
	@echo ""
	@echo "Next: Run 'make phase4-scan' to verify security posture with Trivy"
	@echo ""

phase4-scan:
	$(call say,"Running Trivy scans (manifests + cluster) to verify security posture")
	@echo "Scanning policies directory..."
	@bash scanners/trivy-scan-manifests.sh policies/
	@sleep 2
	@echo "Scanning network-policies directory..."
	@bash scanners/trivy-scan-manifests.sh network-policies/
	@sleep 2
	@echo "Scanning cluster..."
	@bash scanners/trivy-scan-cluster.sh
	@echo ""
	@echo "✅ Phase 4 Complete - All Security Layers Verified!"
	@echo ""
	@echo "🎓 You have successfully completed the BUILD & SECURE phases:"
	@echo "   Phase 1: RBAC, namespaces, and API audit logging"
	@echo "   Phase 2: Pod security policies (Kyverno baseline)"
	@echo "   Phase 3: Network policies (default deny + allows)"
	@echo "   Phase 4: Secrets encryption at rest + hygiene policies"
	@echo ""
	@echo "📋 Next Phase: Phase 5 - Assessment & Attack Simulation"
	@echo "   See the lab workbook for details on vulnerability assessment,"
	@echo "   attack simulations, and security testing strategies."
	@echo ""

phase4-reset: _check-kubectl
	$(call say,"Removing Phase 4 Kyverno policies from cluster only")
	@bash scripts/reset-phase4.sh

phase4-status: _check-kubectl
	$(call say,"Phase 4 policy state")
	@kubectl get cpol,pol -A | grep -i secret || true

phase4-down:
	$(call say,"Deleting k3d cluster '$(K3D_NAME)'")
	@k3d cluster delete "$(K3D_NAME)" || true

# ---- Phase 5: Assessment & Attack Simulation  ---------------------------------

phase5: phase5-assess phase5-simulate

phase5-assess: _check-kubectl
	$(call say,"Running point-in-time security assessment (kube-bench + kubescape)")
	@bash scripts/phase5-assess.sh

phase5-trivy-operator-install: _check-kubectl
	$(call say,"Installing trivy-operator for continuous vulnerability scanning")
	@bash scripts/phase5-trivy-operator-install.sh

phase5-trivy-operator-query: _check-kubectl
	$(call say,"Querying trivy-operator findings")
	@bash scripts/phase5-trivy-operator-query.sh

phase5-simulate: _check-kubectl
	$(call say,"Running attack simulation tests (validates Phase 1-4 controls)")
	@bash scripts/phase5-simulate-attacks.sh

phase5-validate: _check-kubectl
	$(call say,"Hands-on trivy-operator validation guide")
	@echo ""
	@echo "📖 See: docs/phase5-trivy-operator-validation.md"
	@echo ""
	@echo "Run the validation scenarios to:"
	@echo "  1. Deploy insecure workloads"
	@echo "  2. Watch trivy-operator detect issues"
	@echo "  3. Remediate and verify fixes"
	@echo ""
	@echo "Quick test:"
	@echo "  kubectl run test-latest --image=nginx:latest"
	@echo "  # Wait 30-60 seconds for scan"
	@echo "  kubectl get vulnerabilityreports -n default"
	@echo ""

phase5-reset: _check-kubectl
	$(call say,"Cleaning up Phase 5 resources")
	@kubectl delete namespace phase5-tests --ignore-not-found=true || true
	@kubectl delete namespace trivy-system --ignore-not-found=true || true
	@rm -rf reports/phase5-*
	@echo ""
	@echo "✅ Phase 5 resources cleaned up"
	@echo ""

# ---------------------------- Utilities --------------------------------------
status: _check-kubectl
	$(call say,"Cluster status overview")
	@$(KUBECTL) config get-contexts
	@echo "--- Nodes ---"; $(KUBECTL) get nodes -o wide || true
	@echo "--- All namespaces ---"; $(KUBECTL) get ns || true
	@echo "--- Pods (all) ---"; $(KUBECTL) get pods -A -o wide || true

nuke-namespaces: _check-kubectl
	$(call say,"Deleting namespaces: $(NS) demo test sock-shop")
	@$(KUBECTL) delete ns $(NS) demo test sock-shop --ignore-not-found=true || true

reclaim-disk:
	$(call say,"(DANGER) Docker prune images/volumes/builders")
	@read -p "This will remove ALL unused images/volumes/build cache. Continue? [y/N] " ans; \
	if [[ $$ans == y || $$ans == Y ]]; then \
		docker system prune -af --volumes; \
		docker builder prune -af; \
		printf "$(GREEN)Docker disk reclaimed.$(NC)\n"; \
	else \
		printf "$(YELLOW)Skipped.$(NC)\n"; \
	fi

cluster-down:
	$(call say,"Deleting k3d cluster")
	@k3d cluster delete || true

cluster-status:
	$(call say,"k3d cluster status")
	@k3d cluster list
	@kubectl cluster-info || true

# ---------------------------- Guards -----------------------------------------
_check-kubectl:
	@command -v $(KUBECTL) >/dev/null || { printf "$(RED)kubectl not found in PATH$(NC)\n"; exit 1; }
