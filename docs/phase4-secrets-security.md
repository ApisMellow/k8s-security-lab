# Phase 4 — Secrets Hygiene, Encryption at Rest, and Audit

**Goal:** Raise the security bar for Kubernetes secrets: enforce safer patterns with Kyverno, enable **etcd encryption at rest**, and add detection for risky configurations.

---

## What's included

- `scripts/cluster-up-phase4.sh` — **Creates a new k3d cluster** with secrets encryption at rest and API audit logging enabled.
- `scripts/harden-phase4.sh` — Applies Kyverno policies for secret hygiene.
- `scripts/reset-phase4.sh` — Removes Phase 4 resources **from the cluster only** (does **not** delete repo files).
- `policies/phase-4-secrets/` — Kyverno policies:
  - `disallow-env-secrets.yaml` — Blocks common secret-like env var names.
  - `require-secret-names.yaml` — Enforces naming convention for Secret objects.
  - `warn-sensitive-configmap.yaml` — Warns (audit) on sensitive keys in ConfigMaps.

> 🔁 **Why a new cluster?** Enabling encryption at rest requires the API server to start with an `--encryption-provider-config` flag. That’s simplest at **cluster creation time**, so Phase 4 spins up a fresh cluster with those settings pre-baked.

---

## Quick start

```bash
# 1) Spin up an encrypted cluster with audit logging
bash scripts/cluster-up-phase4.sh

# 2) Apply Phase 4 policies
bash scripts/harden-phase4.sh

# 3) Verify
kubectl get cpol,pol -A
```

---

## Verifying encryption at rest

```bash
# Create a test secret (name must match policy: include 'secret-' or '-secret-')
kubectl -n default create secret generic enc-test-secret --from-literal=top=secret

# The k3d cluster is configured to encrypt at rest via --secrets-encryption@server
# The data in etcd should be encrypted by K3s's built-in encryption provider
```

> Important: K3s handles encryption at rest via its built-in provider. The test secret is automatically encrypted when stored in etcd.

---

## Removal / Reset (safe)

- **Cluster resources only:** `scripts/reset-phase4.sh` removes Phase 4 policies from the cluster and deletes test objects.
- **Repo files remain intact.** No script in Phase 4 removes any repository files.

---

## Next steps

- Add External Secrets Operator or SOPS for pull-based secret management.
- Add CI checks (e.g., `kics`, `trivy config`) to catch secrets in YAML before they hit the cluster.
