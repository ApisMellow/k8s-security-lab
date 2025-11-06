
# Kubernetes Security Labs - Convenience Makefile (Phase 1 + Phase 2)
# Targets:
#   ---- Phase 1 ----
#   make up               - create default cluster
#   make up-audit         - create cluster with audit enabled (policy mounted) & localhost API
#   make kubeconfig       - (re)generate project-local kubeconfig
#   make harden           - run Phase 1 hardening verifier
#   make reset            - reset Phase 1 lab state
#   make reset-insecure   - reset + recreate cluster with less-secure defaults
#   make audit            - list audit files on server
#   make audit-tail       - tail last delete entries
#   make logs             - show cluster info
#   make down             - delete cluster
#   make clean            - remove project-local kubeconfig
#
#   ---- Phase 2 ----
#   make p2-harden        - apply PSA labels + install Kyverno + baseline policies (audit)
#   make p2-harden-enforce- same as above but sets policies to enforce
#   make p2-reset         - remove Kyverno policies/labels; uninstall Kyverno (unless --keep-kyverno)

SHELL := /bin/bash
CLUSTER ?= dev
SERVER_CONT ?= k3d-$(CLUSTER)-server-0
KUBECONFIG_FILE := .kube/config
AUDIT_PATH := /var/lib/rancher/k3s/server/logs/audit.log
POLICY := manifests/audit-policy.yaml

# Helper for exporting KUBECONFIG into subcommands
define with_kubeconfig
  export KUBECONFIG=$(PWD)/$(KUBECONFIG_FILE);
endef

.PHONY: up up-audit kubeconfig harden reset reset-insecure audit audit-tail logs down clean \
        p2-harden p2-harden-enforce p2-reset

up:
	@echo "==> Creating cluster '$(CLUSTER)' (default settings)"
	k3d cluster create $(CLUSTER) --image rancher/k3s:v1.30.4-k3s1 --agents 2
	$(with_kubeconfig) mkdir -p .kube && k3d kubeconfig get $(CLUSTER) > $(KUBECONFIG_FILE) && chmod 600 $(KUBECONFIG_FILE)
	$(with_kubeconfig) kubectl cluster-info && kubectl get nodes -o wide

up-audit:
	@echo "==> Recreating cluster '$(CLUSTER)' with audit logging enabled and API bound to localhost"
	-k3d cluster delete $(CLUSTER)
	k3d cluster create $(CLUSTER) \
	  --image rancher/k3s:v1.30.4-k3s1 \
	  --api-port 127.0.0.1:6445 \
	  --agents 2 \
	  --volume "$(PWD)/$(POLICY):/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
	  --k3s-arg "--kube-apiserver-arg=audit-policy-file=/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
	  --k3s-arg "--kube-apiserver-arg=audit-log-path=$(AUDIT_PATH)@server:0" \
	  --k3s-arg "--kube-apiserver-arg=audit-log-maxage=5@server:0" \
	  --k3s-arg "--kube-apiserver-arg=audit-log-maxbackup=5@server:0" \
	  --k3s-arg "--kube-apiserver-arg=audit-log-maxsize=10@server:0"
	$(with_kubeconfig) mkdir -p .kube && k3d kubeconfig get $(CLUSTER) > $(KUBECONFIG_FILE) && chmod 600 $(KUBECONFIG_FILE)
	$(with_kubeconfig) kubectl cluster-info && kubectl get nodes -o wide

kubeconfig:
	@echo "==> Generating project-local kubeconfig"
	$(with_kubeconfig) mkdir -p .kube && k3d kubeconfig get $(CLUSTER) > $(KUBECONFIG_FILE) && chmod 600 $(KUBECONFIG_FILE)
	@echo "   KUBECONFIG=$(PWD)/$(KUBECONFIG_FILE)"

harden:
	@echo "==> Running Phase 1 hardening verifier"
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/harden-phase1.sh

reset:
	@echo "==> Resetting Phase 1 lab state"
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/reset-phase1.sh

reset-insecure:
	@echo "==> Resetting Phase 1 and recreating cluster with less-secure defaults"
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/reset-phase1.sh --insecure-recreate

audit:
	@echo "==> Listing audit files"
	docker exec -i $(SERVER_CONT) sh -c "ls -lh /var/lib/rancher/k3s/server/logs/ | grep audit" || true

audit-tail:
	@echo "==> Tail recent DELETE events from audit log"
	docker exec -i $(SERVER_CONT) sh -c "tail -n 400 $(AUDIT_PATH) | grep '\"verb\":\"delete\"' | tail -n 10" || true

logs:
	@echo "==> kubectl cluster-info"
	$(with_kubeconfig) kubectl cluster-info
	@echo "==> kubectl get nodes"
	$(with_kubeconfig) kubectl get nodes -o wide
	@echo "==> Current context"
	$(with_kubeconfig) kubectl config current-context

down:
	@echo "==> Deleting cluster '$(CLUSTER)'"
	-k3d cluster delete $(CLUSTER)

clean:
	@echo "==> Removing local kubeconfig"
	-rm -f $(KUBECONFIG_FILE)

# ---------- Phase 2 targets ----------

p2-harden:
	@echo "==> Phase 2: PSA labels + Kyverno install + baseline policies (audit mode)"
	$(with_kubeconfig) ./scripts/harden-phase2.sh

p2-harden-enforce:
	@echo "==> Phase 2: switch policies to enforce"
	$(with_kubeconfig) ./scripts/harden-phase2.sh --enforce

p2-reset:
	@echo "==> Phase 2: reset policies and Kyverno (uninstall by default)"
	$(with_kubeconfig) ./scripts/reset-phase2.sh
