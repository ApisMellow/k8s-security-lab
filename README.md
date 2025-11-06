# Kubernetes Security Devbox (Local Lab)

This repo spins up a **local k8s dev cluster** on macOS using **Devbox (Nix)** + **k3d (k3s in Docker)**,
then walks you through **Phase 1** labs: RBAC, namespaces, and basic hardening.

## Prereqs
- macOS with **Nix** and **Devbox** installed
- **Docker Desktop** (or Colima) running (k3d uses a containerized k3s)
- `git` for convenience

> If you want to avoid Docker entirely, see **Alternative: Minikube without Docker** at the end.

## Quickstart

```bash
git clone <this-folder> k8s-sec-devbox
cd k8s-sec-devbox

# enter reproducible toolchain via devbox (kubectl, k3d, helm, k9s, etc.)
devbox shell

# create cluster
./scripts/cluster-up.sh              # default name: dev

# verify
kubectl cluster-info
kubectl get nodes -o wide
```

### Phase 1 Labs

1) **Namespaces + RBAC** (least privilege)

```bash
# create namespaces
kubectl apply -f manifests/namespaces.yaml

# create a restricted role and bind it to a service account in 'dev'
kubectl apply -f manifests/rbac-dev-view.yaml

# test permissions as the service account
kubectl -n dev auth can-i list pods --as=system:serviceaccount:dev:sa-dev-view
kubectl -n dev auth can-i delete pods --as=system:serviceaccount:dev:sa-dev-view  # should be no
```

2) **API Audit Logging with k3d/k3s**

```bash
# destroy any existing cluster
./scripts/cluster-down.sh

# recreate with audit logging enabled and audit policy mounted, set apiserver arg
# flags for k3s via k3d so audit lines are easier to see
./scripts/cluster-up-with-audit.sh

# generate some denied events, then check logs:
kubectl -n dev auth can-i delete secrets --as=system:serviceaccount:dev:sa-dev-view
# peek at the server node logs for 'audit'
docker logs $(docker ps --filter name=k3d-dev-server-0 -q) 2>&1 | grep audit
```
> Audit files in k3s live under `/var/lib/rancher/k3s/server/logs/audit.log` inside the server node.
> We pass args via `--k3s-arg` to configure the apiserver.

### Teardown

```bash
./scripts/cluster-down.sh
```

---

## Alternative: Minikube without Docker

If you don't want Docker Desktop, you can run **minikube** with a VM driver (qemu/hyperkit). Inside `devbox shell`:

```bash
devbox add minikube
minikube start --driver=qemu
kubectl get nodes
```

> Note: paths and flags for audit logging differ from k3s. Start with the k3d path for speed; switch later if needed.

## Notes

- RBAC is **enabled by default** in modern Kubernetes/k3s; the lab teaches you how to **verify and scope privileges**.
- This setup keeps everything **ephemeral and reproducible**; wipe and recreate clusters freely.
- Devbox pins your toolchain so teammates get the same `kubectl`, `k3d`, etc.
