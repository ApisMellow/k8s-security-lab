# Kyverno Policies (by Phase)

This folder organizes Kyverno ClusterPolicies by security phase.

## phase-2-baseline/

Basic Pod Security policies applied in Phase 2:

- **disallow-privileged.yaml** — Blocks privileged containers.
- **disallow-root-user.yaml** — Requires `runAsNonRoot: true` or a container `runAsUser > 0`.
- **restrict-image-registry.yaml** — Restricts images to `ghcr.io/*` or `docker.io/library/*`.
- **require-labels.yaml** — Requires an `app` label on common workload kinds.
- **disallow-hostpath.yaml** — Prevents hostPath volume mounts.
- **drop-net-raw-capability.yaml** — Drops NET_RAW capability from containers.

All policies ship with `validationFailureAction: audit`.
Flip to **enforce** by search‑replacing `audit` → `enforce` or use `./scripts/harden-phase2.sh --enforce`.

Apply:
```bash
make phase2-apply
# or manually:
kubectl apply -f ./policies/phase-2-baseline/
```

## phase-4-secrets/

Secrets hygiene & encryption policies applied in Phase 4:

- **disallow-env-secrets.yaml** — Prevents hardcoded secrets in environment variables.
- **require-secret-names.yaml** — Enforces naming conventions for Secret objects.
- **warn-sensitive-configmap.yaml** — Warns when ConfigMaps contain sensitive data.

Apply:
```bash
make phase4-harden
# or manually:
kubectl apply -f ./policies/phase-4-secrets/
```

## Check Policies

```bash
kubectl get clusterpolicies
kubectl get policyreport -A -o wide
```
