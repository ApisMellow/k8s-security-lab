# Kubernetes Security Labs - Phase 1 Automation
# Targets:
#   make up             - create basic cluster
#   make up-audit       - create hardened cluster with audit logging
#   make kubeconfig     - regenerate .kube/config
#   make harden         - run verifier
#   make reset          - remove lab changes
#   make reset-insecure - reset + insecure cluster recreate
#   make audit          - list audit logs
#   make audit-tail     - tail last delete events
#   make down           - delete cluster
#   make clean          - remove .kube/config

SHELL := /bin/bash
CLUSTER ?= dev
SERVER_CONT ?= k3d-$(CLUSTER)-server-0
KUBECONFIG_FILE := .kube/config
AUDIT_PATH := /var/lib/rancher/k3s/server/logs/audit.log
POLICY := manifests/audit-policy.yaml

define with_kubeconfig
  export KUBECONFIG=$(PWD)/$(KUBECONFIG_FILE);
endef

.PHONY: up up-audit kubeconfig harden reset reset-insecure audit audit-tail down clean

up:
	@echo "==> Creating cluster $(CLUSTER)"
	k3d cluster create $(CLUSTER) --image rancher/k3s:v1.30.4-k3s1 --agents 2
	$(with_kubeconfig) mkdir -p .kube && k3d kubeconfig get $(CLUSTER) > $(KUBECONFIG_FILE) && chmod 600 $(KUBECONFIG_FILE)

up-audit:
	@echo "==> Creating hardened cluster $(CLUSTER) with audit logging and localhost API"
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

kubeconfig:
	$(with_kubeconfig) mkdir -p .kube && k3d kubeconfig get $(CLUSTER) > $(KUBECONFIG_FILE) && chmod 600 $(KUBECONFIG_FILE)
	@echo "Generated kubeconfig for $(CLUSTER)"

harden:
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/harden-phase1.sh

reset:
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/reset-phase1.sh

reset-insecure:
	$(with_kubeconfig) SERVER_CONT=$(SERVER_CONT) ./scripts/reset-phase1.sh --insecure-recreate

audit:
	docker exec -i $(SERVER_CONT) sh -c "ls -lh /var/lib/rancher/k3s/server/logs | grep audit" || true

audit-tail:
	docker exec -i $(SERVER_CONT) sh -c "tail -n 400 $(AUDIT_PATH) | grep '\"verb\":\"delete\"' | tail -n 10" || true

down:
	-k3d cluster delete $(CLUSTER)

clean:
	rm -f $(KUBECONFIG_FILE)

