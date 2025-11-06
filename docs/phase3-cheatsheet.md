# Phase 3 Cheat Sheet — Network Segmentation & Egress Controls

**Objective:**  
Lock down east–west traffic and outbound internet access using Kubernetes NetworkPolicies.  
Default = deny everything, then selectively allow what’s required (DNS, intra-namespace, specific apps, controlled egress).

---

## 🧩 Key Concepts

| Area | Purpose | Files |
|------|----------|-------|
| **Default Deny** | Block all ingress/egress by default | `00-default-deny-ingress.yaml`, `01-default-deny-egress.yaml` |
| **DNS Egress** | Allow DNS queries to kube-dns | `10-allow-dns-egress.yaml` |
| **Intra-Namespace** | Permit pods in same ns to talk | `20-allow-same-namespace.yaml` |
| **App-to-App** | Allow front-end → back-end | `30-allow-app-to-app.yaml` |
| **External Egress** | (Optional) HTTPS to internet | `40-allow-egress-external.yaml` |

---

## 🧭 Common Make Commands

| Command | Description |
|----------|-------------|
| `make phase3` | Alias → `make phase3-harden` |
| `make phase3-harden` | Runs `scripts/harden-phase3.sh`; verifies CNI + applies baseline |
| `make phase3-apply` | Applies baseline NetworkPolicies from `network-policies/` |
| `make phase3-reset` | Deletes all Phase 3 NetworkPolicies |
| `make phase3-status` | Lists NetworkPolicies + pods in dev/prod |
| `make phase3-test` | Demo frontend↔backend connectivity checks |
| `make phase3-diff` | Shows `kubectl diff` changes before apply |
| `make phase3-lint` | Lints YAML (uses yamllint if available) |

---

## 🧪 Test Sequence

```bash
# Create namespaces if missing
kubectl create ns dev || true
kubectl create ns prod || true

# 1️⃣  Apply baseline
make phase3-harden

# 2️⃣  Deploy demo pods
kubectl -n dev run backend --image=nginx --labels app=backend -- sh -lc 'nginx -g "daemon off;"'
kubectl -n dev run frontend --image=busybox --labels app=frontend --restart=Never -- sh -lc 'sleep 3600'

# 3️⃣  Check connectivity (should FAIL initially)
kubectl -n dev exec frontend -- wget -S -O- http://backend:8080 2>&1 | head -n2

# 4️⃣  Allow app-to-app traffic
kubectl -n dev apply -f network-policies/30-allow-app-to-app.yaml

# 5️⃣  Retry (should SUCCEED)
kubectl -n dev exec frontend -- wget -S -O- http://backend:8080 2>&1 | head -n2

# 6️⃣  Block outbound traffic (default-deny)
kubectl -n dev exec frontend -- wget -qO- https://example.com || echo "blocked (expected)"

# 7️⃣  Allow controlled egress (optional)
kubectl -n dev apply -f network-policies/40-allow-egress-external.yaml
kubectl -n dev exec frontend -- wget -qO- https://example.com | head -n1

