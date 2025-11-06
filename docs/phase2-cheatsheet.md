

---

## 5.5) Policy tests (quick PASS/FAIL demos)

### A) **Disallow hostPath** (should be **denied** in enforce; **reported** in audit)
```bash
kubectl -n dev run hostpath-test --image=busybox --restart=Never   --overrides='{
    "spec":{
      "volumes":[{"name":"h","hostPath":{"path":"/"}}],
      "containers":[{"name":"b","image":"busybox","command":["sh","-c","sleep 10"],
        "volumeMounts":[{"name":"h","mountPath":"/host"}]}]}}'
# Expect: Forbidden (enforce), or admitted + PolicyReport (audit)
```

### B) **Drop NET_RAW** mutation (should be added automatically)
```bash
kubectl -n dev run netraw-test --image=busybox --restart=Never -- sh -lc 'sleep 3600'
kubectl -n dev get pod netraw-test -o yaml | grep -A6 "capabilities:"
# Expect: capabilities.drop contains NET_RAW

# Opt out (allowed for break-glass scenarios)
kubectl -n dev run netraw-allow --image=busybox --restart=Never   --overrides='{
    "metadata":{"annotations":{"kyverno.io/allow-net-raw":"true"}},
    "spec":{"containers":[{"name":"c","image":"busybox","command":["sh","-c","sleep 3600"]}]}}'
kubectl -n dev get pod netraw-allow -o yaml | grep -A6 "capabilities:"
# Expect: no automatic drop NET_RAW on this pod
```

### C) **Require labels** (missing `app` should be denied in enforce; reported in audit)
```bash
kubectl -n dev run nolabels --image=nginx --restart=Never
# Expect: Forbidden (enforce) or PolicyReport (audit)

# Compliant example
kubectl -n dev run haslabel --image=nginx --restart=Never --labels app=demo
```

### D) **Restrict image registry** (non-allowed registry should be denied/report)
```bash
# This image path fails the allowlist (unless you adjust policy):
kubectl -n dev run badimg --image=quay.io/libpod/busybox:latest --restart=Never
# Expect: Forbidden (enforce) or PolicyReport (audit)

# Allowed examples
kubectl -n dev run ok1 --image=docker.io/library/nginx:latest --restart=Never
kubectl -n dev run ok2 --image=ghcr.io/stefanprodan/podinfo:latest --restart=Never
```

### Cleanup test artifacts
```bash
kubectl -n dev delete pod hostpath-test netraw-test netraw-allow nolabels haslabel badimg ok1 ok2 --ignore-not-found=true
```
