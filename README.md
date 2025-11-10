# Kubernetes Security Devbox (Local Lab)

This repo spins up a **local k8s dev cluster** on macOS using **Devbox (Nix)** + **k3d (k3s in Docker)**,
then walks you through **Phase 1** labs: RBAC, namespaces, and basic hardening.

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

# run all phases in sequence
make phase1 phase2 phase3 phase4
```

This runs the full security lab from Phase 1 (RBAC, namespaces, audit) through Phase 4 (encryption at rest, secret hygiene).

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
```

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

## Notes

- RBAC is **enabled by default** in modern Kubernetes/k3s; the lab teaches you how to **verify and scope privileges**.
- This setup keeps everything **ephemeral and reproducible**; wipe and recreate clusters freely.
- Devbox pins your toolchain so teammates get the same `kubectl`, `k3d`, etc.
