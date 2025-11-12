# Phase 5: Trivy-Operator Hands-On Validation Guide

This guide shows you how to manually test trivy-operator by deploying insecure workloads, watching the operator detect them, and then remediating them.

This hands-on approach helps you understand:
- How trivy-operator continuously monitors your cluster
- What kinds of security issues it detects
- How quickly it responds to changes
- How to remediate findings

**Time estimate**: 15-20 minutes

---

## Prerequisites

Before starting:
1. Cluster should be running Phase 4: `make phase4`
2. trivy-operator should be installed: `make phase5-trivy-operator-install`
3. Initial scans should be complete (wait 2-5 minutes after install)
4. Verify operator is running: `kubectl get pods -n trivy-system`

---

## Validation Test 1: Image with Latest Tag

### Scenario
You accidentally deploy `nginx:latest` (bad practice - should pin version).

### Step 1: Deploy Insecure Pod
```bash
kubectl -n default run test-latest --image=nginx:latest --restart=Never
```

### Step 2: Wait for Scan
Wait 30-60 seconds for trivy-operator to scan the pod.

```bash
# Monitor scan progress
watch kubectl get vulnerabilityreports -n default
```

### Step 3: Check What trivy-operator Found

```bash
# See vulnerability reports
kubectl get vulnerabilityreports -n default -o wide

# Get detailed findings
kubectl describe vulnerabilityreport -n default pod-test-latest

# View as JSON for full details
kubectl get vulnerabilityreport -n default pod-test-latest -o yaml | jq '.report'
```

### Expected Findings
- **Finding**: "Using image tag 'latest' is not recommended"
- **Severity**: MEDIUM
- **Potential CVEs**: May show 2-10 vulnerabilities depending on image
- **Details**: List of specific CVEs with CVSS scores

### Step 4: Understand the Risk

**Why is `:latest` bad?**
- You don't know which version is running
- Image changes without your knowledge (might introduce vulnerabilities)
- Hard to debug issues (which version was running when?)
- Rebuilds use different base images (inconsistent)

**What's the risk?**
- Container might include unpatched vulnerabilities
- Upgrading image might break application
- No reproducibility across environments

### Step 5: Remediate

Update to a specific pinned version:

```bash
# Option 1: Delete and redeploy with pinned version
kubectl delete pod test-latest -n default
kubectl run test-pinned --image=nginx:1.27-alpine --restart=Never

# Option 2: If using Deployment, patch it
kubectl set image deployment/test-latest test-latest=nginx:1.27-alpine
```

### Step 6: Verify Fix

Wait 30 seconds, then check the new report:

```bash
kubectl get vulnerabilityreports -n default

# The new report should have:
# - Same or fewer vulnerabilities (depending on base image version)
# - No "latest tag" warning
# - Specific version documented
```

### Learning Points
✅ trivy-operator detects image tag issues automatically
✅ Specific pinned versions are more secure
✅ Alpine images have fewer vulnerabilities than standard images
✅ Operator rescans automatically when pods change

---

## Validation Test 2: Pod Without Security Context

### Scenario
You deploy a pod without security hardening (runs as root, allows privilege escalation).

### Step 1: Deploy Insecure Pod

```bash
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:1.27-alpine
    # ❌ NO securityContext - will run as root!
EOF
```

### Step 2: Wait for Configuration Audit

trivy-operator will scan the pod and create a ConfigAuditReport.

```bash
# Watch for configuration audit reports
watch kubectl get configauditreports -n default

# This may take 1-2 minutes
```

### Step 3: Check What trivy-operator Found

```bash
# See the report
kubectl get configauditreports -n default -o wide

# Get detailed findings
kubectl describe configauditreport -n default pod-root-pod

# View specific controls that failed
kubectl get configauditreport -n default pod-root-pod -o yaml | \
  jq '.report.checks[] | select(.success==false)'
```

### Expected Findings
```
- "Container should run as non-root user" (MEDIUM)
- "No securityContext defined" (MEDIUM)
- "allowPrivilegeEscalation should be false" (MEDIUM)
- "readOnlyRootFilesystem should be true" (LOW)
```

### Step 4: Understand the Risks

**Running as root is dangerous because:**
- Attackers can modify system files
- Easier to escape container and compromise host
- Violates principle of least privilege
- Most apps don't need root (nginx, node.js, etc. can run as any user)

**Missing security context means:**
- Process can escalate privileges
- Process can write to root filesystem
- Pod has unnecessary capabilities enabled

### Step 5: Remediate

Apply security hardening:

```bash
# Delete the insecure pod
kubectl delete pod root-pod -n default

# Deploy with security hardening
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 101  # nginx user
    fsGroup: 101
  containers:
  - name: app
    image: nginx:1.27-alpine
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 101
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

### Step 6: Verify Fix

```bash
# Check the new configuration audit report
kubectl describe configauditreport -n default pod-root-pod

# Should now show:
# ✅ "Container should run as non-root user" - PASSED
# ✅ "allowPrivilegeEscalation" - PASSED
# ✅ Better security posture
```

### Learning Points
✅ Security context enforces privilege boundaries
✅ Non-root user reduces attack surface
✅ readOnlyRootFilesystem prevents modifications
✅ Dropping ALL capabilities is defense-in-depth
✅ trivy-operator validates CIS Benchmark controls

---

## Validation Test 3: Secrets in Environment Variables

### Scenario
You (accidentally or intentionally) expose secrets via environment variables - a common mistake.

### Step 1: Deploy Pod with Secret in Env Var

```bash
# Create the secret first
kubectl create secret generic db-password \
  -n default \
  --from-literal=password=super-secret-123

# Deploy pod using it as environment variable (BAD!)
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:1.27-alpine
    env:
    - name: DATABASE_PASSWORD  # ❌ Secret in env var!
      valueFrom:
        secretKeyRef:
          name: db-password
          key: password
EOF
```

### Step 2: Wait for Detection

```bash
# Watch for secret reports and config audits
watch kubectl get secretreports,configauditreports -n default
```

### Step 3: Check What trivy-operator Found

```bash
# View secret exposure reports
kubectl get secretreports -n default -o wide

# Get detailed findings
kubectl describe secretreport -n default pod-secret-env-pod

# View configuration audit for the same pod
kubectl describe configauditreport -n default pod-secret-env-pod | grep -A5 "Environment"
```

### Expected Findings
```
- "Sensitive environment variable detected" (HIGH)
  Variable: DATABASE_PASSWORD
  Risk: Exposed in:
    - kubectl describe pod
    - Pod logs
    - Container inspect
    - Monitoring/metrics
    - Core dumps
```

### Step 4: Understand the Risk

**Why environment variables leak secrets:**
- Visible in `kubectl describe pod`
- Visible in `docker inspect` on node
- May be logged by applications
- Appear in core dumps and debugging output
- Visible to any process with access to /proc/[pid]/environ
- Hard to audit - no easy way to find all secret env vars

**Better approaches:**
- Volume mounts (secrets mounted as files)
- External secrets operator (fetch at runtime)
- Service mesh injection
- Environment variable from ConfigMap only (non-secret data)

### Step 5: Remediate

Use volume mounts instead:

```bash
# Delete the insecure pod
kubectl delete pod secret-env-pod -n default

# Deploy using volume mounts (GOOD!)
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:1.27-alpine
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true
    # Application reads /etc/secrets/password instead of env var
  volumes:
  - name: secrets
    secret:
      secretName: db-password
      defaultMode: 0400  # Only owner can read
EOF
```

### Step 6: Verify Fix

```bash
# Check if secret report is still present
kubectl get secretreports -n default

# Should no longer show secret exposure
# (or report should disappear after pod is updated)

# Verify the secret is mounted
kubectl exec -it secret-env-pod -- ls -la /etc/secrets/
kubectl exec -it secret-env-pod -- cat /etc/secrets/password
```

### Learning Points
✅ Never use environment variables for secrets
✅ trivy-operator detects secret exposure patterns
✅ Volume mounts are safer than env vars
✅ Secrets are not logged when mounted as files
✅ Phase 4 policy (`disallow-env-secrets`) enforces this

---

## Validation Test 4: Deploy Image with Known CVE

### Scenario
You deploy an old version of an application with known vulnerabilities.

### Step 1: Deploy Vulnerable Image

```bash
# nginx 1.19.0 has known CVEs
kubectl run vulnerable-image --image=nginx:1.19.0 --restart=Never
```

### Step 2: Wait for Vulnerability Scan

This may take 2-5 minutes for trivy-operator to scan.

```bash
# Monitor scan
watch kubectl get vulnerabilityreports -n default

# Once report appears, stop watching
```

### Step 3: Check Findings

```bash
# View vulnerability report
kubectl describe vulnerabilityreport -n default pod-vulnerable-image

# See all vulnerabilities
kubectl get vulnerabilityreport -n default pod-vulnerable-image -o yaml | \
  jq '.report.vulnerabilities[] | select(.severity=="CRITICAL" or .severity=="HIGH")'
```

### Expected Findings
```
Multiple CVEs including (example):
- CVE-2021-4034 (CRITICAL)
- CVE-2021-44228 (CRITICAL) - Log4Shell
- Several HIGH severity CVEs
```

### Step 4: Understand the Risk

**Old images accumulate CVEs:**
- Security patches released regularly
- Old versions have known exploits
- Attackers can target specific CVEs
- No excuse to run old versions (easy to update)

**Why this matters in production:**
- Compromised application leads to data breach
- Host compromise possible if vulnerabilities allow escape
- Regulatory compliance issues (PCI-DSS, HIPAA, SOC2)
- Ransomware targets known CVEs in unpatched systems

### Step 5: Remediate

Update to patched version:

```bash
# Delete old pod
kubectl delete pod vulnerable-image -n default

# Deploy with current version
kubectl run patched-image --image=nginx:1.27-alpine --restart=Never

# Wait 1-2 minutes for new scan
```

### Step 6: Verify Fix

```bash
# Check new vulnerability report
kubectl describe vulnerabilityreport -n default pod-patched-image

# Should show:
# ✅ Significantly fewer vulnerabilities
# ✅ No CRITICAL findings (usually)
# ✅ Much lower overall risk
```

### Learning Points
✅ Old images have known exploits
✅ trivy-operator tracks CVE databases automatically
✅ Keep images updated and regularly patched
✅ Alpine images typically have fewer vulnerabilities
✅ Phase 4 scanning (`make phase4-scan`) runs Trivy, trivy-operator runs continuously

---

## Summary: What You've Learned

By running these 4 validation tests, you've seen:

| Test | What Trivy-Operator Detected | Time | Key Takeaway |
|------|------------------------------|------|--------------|
| **Test 1** | Image tag best practice violation | 30-60s | Use specific versions, not latest |
| **Test 2** | Missing security context controls | 1-2min | Harden pods with security context |
| **Test 3** | Secrets in environment variables | 1-2min | Use volume mounts for secrets |
| **Test 4** | Known CVEs in old image | 2-5min | Keep images updated and patched |

### Key Insights

1. **Continuous Monitoring Matters**
   - trivy-operator catches issues immediately
   - No need to remember to run scans manually
   - Can trigger alerts/remediations automatically

2. **Multiple Detection Layers**
   - Image vulnerability scanning (CVEs)
   - Configuration audit (CIS Benchmarks)
   - Secret exposure detection
   - RBAC assessment
   - All without running separate tools

3. **Remediation is Visible**
   - Deploy fix
   - Operator rescans automatically
   - Reports update in real-time
   - Can verify fix worked

4. **Production Ready**
   - trivy-operator is designed for continuous monitoring
   - Can export results to monitoring systems
   - Can set SLAs for fixing findings
   - Better than point-in-time assessments

---

## Cleanup

After validating, clean up test pods:

```bash
# Delete all test pods
kubectl delete pod --all -n default --ignore-not-found=true

# Or specific pods
kubectl delete pod test-latest root-pod secret-env-pod vulnerable-image -n default --ignore-not-found=true
```

---

## Next Steps

1. **Understand the bigger picture**: Read `docs/phase5-assessment-guide.md`
2. **See how findings map to controls**: Read `docs/phase5-control-mapping.md`
3. **Use trivy-operator in production**:
   - Export findings to monitoring (Prometheus, Grafana)
   - Set SLAs for fixing CRITICAL/HIGH findings
   - Automate remediation where possible
   - Regular image updates and scanning

---

## Troubleshooting

### "No reports found even after 5 minutes"
- Check operator is running: `kubectl get pods -n trivy-system`
- Check logs: `kubectl logs -n trivy-system deploy/trivy-operator`
- Increase wait time (initial scan can take longer)

### "Reports show but I expected different findings"
- Different versions of images have different CVEs
- Check the specific CVE database version: `trivy version`
- Some findings depend on image OS/packages

### "I can't execute commands in pod"
- Pod may not have a shell (`nginx:alpine` is minimal)
- Try: `kubectl exec -it pod-name -- sh`
- Or use `busybox` for testing instead

