# Unified Makefile for Kubernetes Security Lab (Phase 2 + Phase 3)
SHELL := /usr/bin/env bash

# ---------------------------- Config -----------------------------------------
KUBECTL        ?= kubectl
NS             ?= dev prod
POLICY_DIR     ?= policy               # Phase 2 Kyverno policies (your yaml folder)
NP_DIR         ?= network-policies     # Phase 3 NetworkPolicies
KYVERNO_NS     ?= kyverno

# Colors
YELLOW := \033[33m
GREEN  := \033[32m
CYAN   := \033[36m
RED    := \033[31m
NC     := \033[0m

define say
	@printf "$(CYAN)[make]$(NC) %s\n" "$(1)"
endef

.PHONY: help \
        phase2 phase2-harden phase2-apply phase2-reset phase2-status phase2-diff phase2-lint \
        phase3 phase3-harden phase3-apply phase3-reset phase3-status phase3-test phase3-diff phase3-lint \
        status nuke-namespaces reclaim-disk spin-down resume-notes _check-kubectl

# ---------------------------- Help -------------------------------------------
help:
	@echo "Targets:"
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
	@echo "  status            - Cluster high-level status (contexts, nodes, ns, pods)"
	@echo "  nuke-namespaces   - Delete common demo namespaces (config NS=...)"
	@echo "  reclaim-disk      - Docker prune images/volumes/builders (DANGEROUS)"
	@echo "  spin-down         - Guidance: stop/delete local cluster (kind/minikube/k3d)"
	@echo "  resume-notes      - Guidance: how to resume work later"

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

# Print guidance to spin down (can also just run: make spin-down)
spin-down:
	@echo "== Guidance to spin down local Kubernetes =="
	@echo "1) Phase cleanup: make phase3-reset && make phase2-reset"
	@echo "2) Remove demo namespaces: make nuke-namespaces"
	@echo "3) Stop or delete your cluster:"
	@echo "   - kind:     kind delete cluster [--name <name>]"
	@echo "   - minikube: minikube stop && minikube delete --all"
	@echo "   - k3d:      k3d cluster delete <name>"
	@echo "   - Docker Desktop: disable Kubernetes in Settings > Kubernetes"
	@echo "4) Optional disk cleanup: make reclaim-disk"
	@echo "5) To resume later: start cluster (kind/minikube/k3d) and run 'make phase2 && make phase3'"

resume-notes:
	@echo "== How to resume later =="
	@echo "1) Start your cluster (pick one):"
	@echo "   - kind:     kind create cluster [--name <name>]"
	@echo "   - minikube: minikube start"
	@echo "   - k3d:      k3d cluster create <name>"
	@echo "   - Docker Desktop: enable Kubernetes in Settings > Kubernetes"
	@echo "2) Apply security baselines:"
	@echo "   make phase2 && make phase3"
	@echo "3) Verify:"
	@echo "   make phase2-status && make phase3-status"
	@echo "4) Per-app policies: add/adjust NetworkPolicies under $(NP_DIR)/ as needed."

# ---------------------------- Guards -----------------------------------------
_check-kubectl:
	@command -v $(KUBECTL) >/dev/null || { printf "$(RED)kubectl not found in PATH$(NC)\n"; exit 1; }
