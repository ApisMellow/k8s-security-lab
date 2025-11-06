# Kyverno Policy Set (Phase 2 Baseline)

This folder contains four example baseline policies used in Phase 2:

- **disallow-privileged.yaml** — Blocks privileged containers.
- **disallow-root-user.yaml** — Requires `runAsNonRoot: true` or a container `runAsUser > 0`.
- **restrict-image-registry.yaml** — Restricts images to `ghcr.io/*` or `docker.io/library/*` using `foreach` element validation.
- **require-labels.yaml** — Requires an `app` label on common workload kinds.

All policies ship with `validationFailureAction: audit`.  
Flip to **enforce** by search‑replacing `audit` → `enforce` or use `./scripts/harden-phase2.sh --enforce`.

Apply:
```bash
kubectl apply -f ./policies/
```

Check:
```bash
kubectl get clusterpolicies
kubectl get policyreport -A -o wide
```
