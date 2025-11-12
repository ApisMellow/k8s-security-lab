# Kubernetes Security Devbox (Local Lab)

This repo spins up a **local k8s dev cluster** on macOS using **Devbox (Nix)** + **k3d (k3s in Docker)**,
then walks you through **5 phases** of security hardening: from RBAC and namespaces through encryption, network policies, and continuous security assessment.

## Prereqs
- macOS with **Nix** and **Devbox** installed
- **Docker Desktop** running (k3d uses a containerized k3s)
- `git` for convenience

## Getting Started

### Option 1: Automated Path (Makefile) — Recommended

The fastest way to run all phases:

```bash
git clone <this-folder> k8s-sec-devbox
cd k8s-sec-devbox

# enter reproducible toolchain
devbox shell

# Phase 1-3: Build progressive hardening (same cluster)
make phase1 phase2 phase3

# Phase 4: Recreate cluster with encryption at rest
make cluster-down
make phase4

# Phase 5: Security assessment and validation
make phase5-assess
make phase5-trivy-operator-install
make phase5-trivy-operator-query
make phase5-simulate
```

**Phase progression**:
1. **Phases 1-3**: Build security controls incrementally (RBAC → Pod Security → Network Policies)
2. **Phase 4**: Start fresh cluster with encryption enabled at creation time
3. **Phase 5**: Assess security posture with kube-bench, kubescape, and trivy-operator

Check help for individual phases:
```bash
make help
```

### Option 2: Manual Path (Scripts) — For Learning

If you want to understand each step, run scripts manually:

```bash
git clone <this-folder> k8s-sec-devbox
cd k8s-sec-devbox

devbox shell

# Phase 1a: Create basic cluster
./scripts/cluster-up-phase1-basic.sh

# Phase 1b: Upgrade to audit logging
./scripts/cluster-down.sh
./scripts/cluster-up-phase1-with-audit.sh

# Phase 1: Apply RBAC and test
kubectl apply -f manifests/namespaces.yaml
kubectl apply -f manifests/rbac-dev-view.yaml
bash scripts/harden-phase1.sh

# Phase 2: Add pod security & Kyverno policies
bash scripts/harden-phase2.sh

# Phase 3: Add network policies
bash scripts/harden-phase3.sh

# Phase 4: Enable encryption at rest + secret hygiene
./scripts/cluster-up-phase4.sh
bash scripts/harden-phase4.sh

# Phase 5: Security assessment and validation
bash scripts/phase5-assess.sh
bash scripts/phase5-trivy-operator-install.sh
bash scripts/phase5-trivy-operator-query.sh
bash scripts/phase5-simulate-attacks.sh
```

---

## Phase Overview

| Phase | Focus | Controls | Cluster |
|-------|-------|----------|---------|
| **1** | RBAC & Audit | Role-based access control, namespace isolation, API audit logging | Same |
| **2** | Pod Security | Privileged container blocking, non-root enforcement, capability dropping | Same |
| **3** | Network Policies | Default deny ingress/egress, namespace isolation, zero-trust networking | Same |
| **4** | Encryption & Secrets | Encryption at rest, secret naming enforcement, secret hygiene policies | **New** (encryption enabled) |
| **5** | Assessment | Security audit, continuous monitoring, attack validation | Existing |

---

## Phase 1 Lab Details

### 1) **Namespaces + RBAC** (least privilege)

```bash
# create namespaces
kubectl apply -f manifests/namespaces.yaml

# create a restricted role and bind it to a service account in 'dev'
kubectl apply -f manifests/rbac-dev-view.yaml

# test permissions as the service account
kubectl -n dev auth can-i list pods --as=system:serviceaccount:dev:sa-dev-view
kubectl -n dev auth can-i delete pods --as=system:serviceaccount:dev:sa-dev-view  # should be no
```

### 2) **API Audit Logging with k3d/k3s**

```bash
# destroy any existing cluster
./scripts/cluster-down.sh

# recreate with audit logging enabled and audit policy mounted, set apiserver arg
# flags for k3s via k3d so audit lines are easier to see
./scripts/cluster-up-phase1-with-audit.sh

# generate some denied events, then check logs:
kubectl -n dev auth can-i delete secrets --as=system:serviceaccount:dev:sa-dev-view
# peek at the server node logs for 'audit'
docker logs $(docker ps --filter name=k3d-dev-server-0 -q) 2>&1 | grep audit
```
> Audit files in k3s live under `/var/lib/rancher/k3s/server/logs/audit.log` inside the server node.
> We pass args via `--k3s-arg` to configure the apiserver.

## Phase 4: Encryption & Secrets Hygiene

After Phase 4, run security scans to verify your controls:

```bash
make phase4-scan
```

If you wish to save the report to disk:

```bash
make phase4-scan > phase4-scan-$(date +%Y%m%d-%H%M%S).txt 2>&1
```

## Phase 5: Security Assessment & Validation

Once you've hardened your cluster through Phases 1-4, Phase 5 validates that your security controls actually work.

### What Phase 5 Does

**Security Assessment Tools**:
- **kube-bench**: Audits cluster against CIS Kubernetes Benchmark (100+ checks)
- **kubescape**: Multi-framework assessment (CIS, NSA-CISA, MITRE ATT&CK, SOC2)
- **trivy-operator**: Continuous vulnerability scanning, configuration audits, secret detection

**Attack Validation**:
- Test 1: RBAC enforcement (Phase 1 controls)
- Test 2: Pod security policies (Phase 2 controls)
- Test 3: Network isolation (Phase 3 controls)
- Test 4: Secret hygiene (Phase 4 controls)

**Hands-on Learning**:
- Deploy insecure workloads
- Watch trivy-operator detect issues
- Remediate and verify fixes

### Quick Start

```bash
# Assessment (point-in-time)
make phase5-assess

# Continuous monitoring (install operator)
make phase5-trivy-operator-install
make phase5-trivy-operator-query

# Validate controls prevent attacks
make phase5-simulate

# Hands-on testing
make phase5-validate
# Then follow: docs/phase5-trivy-operator-validation.md
```

### Documentation

- **docs/phase5-assessment-guide.md** - Understand kube-bench, kubescape, trivy-operator
- **docs/phase5-control-mapping.md** - How Phases 1-4 controls address findings
- **docs/phase5-trivy-operator-validation.md** - Hands-on validation guide with scenarios
- **docs/phase5-cheatsheet.md** - Quick reference for all Phase 5 commands

## Notes

- RBAC is **enabled by default** in modern Kubernetes/k3s; the lab teaches you how to **verify and scope privileges**.
- This setup keeps everything **ephemeral and reproducible**; wipe and recreate clusters freely.
- Devbox pins your toolchain so teammates get the same `kubectl`, `k3d`, etc.
