# Phase 4 Cheat Sheet — Secrets & Encryption

## Commands

```bash
# Create new encrypted cluster with audit logging
bash scripts/cluster-up-phase4.sh

# Apply Phase 4 policies
bash scripts/harden-phase4.sh

# Check status
kubectl get cpol,pol -A

# Create a test secret and sanity check
kubectl -n default create secret generic enc-test --from-literal=top=secret

# Remove Phase 4 resources from cluster (not repo files)
bash scripts/reset-phase4.sh
```

## Policies & Intent

- **disallow-env-secrets.yaml** — Block env var keys that look like secrets (PASSWORD, TOKEN, KEY, SECRET, API_KEY, ACCESS_KEY).
- **require-secret-names.yaml** — Secrets must include `-secret-` or `secret-` in names to be obvious in inventory.
- **warn-sensitive-configmap.yaml** — Audit only, flags suspicious keys in ConfigMaps to discourage misuse.

## Resume later

1. Recreate encrypted cluster: `bash scripts/cluster-up-phase4.sh`
2. Reapply policies: `bash scripts/harden-phase4.sh`
