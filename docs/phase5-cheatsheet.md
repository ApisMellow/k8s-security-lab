# Phase 5: Quick Reference Cheatsheet

## Quick Start Workflow

```bash
# Prerequisites: Phase 4 cluster running
make phase4

# 1. Point-in-time assessment (8 minutes)
make phase5-assess

# Review reports in: reports/phase5-assessment/TIMESTAMP/

# 2. Install continuous monitoring (5 minutes)
make phase5-trivy-operator-install

# 3. Query and compare findings (2 minutes)
make phase5-trivy-operator-query

# 4. Run attack validation tests (5 minutes)
make phase5-simulate

# 5. Hands-on validation (15 minutes)
make phase5-validate
# Then follow: docs/phase5-trivy-operator-validation.md

# Total time: ~45 minutes
```

---

## Assessment Tools

### kube-bench (CIS Compliance)
```bash
# Run via phase5-assess
make phase5-assess

# View results
jq '.Results[] | select(.status=="FAIL")' \
  reports/phase5-assessment/TIMESTAMP/kube-bench-results.json

# Interpret output
[PASS]   - Configuration complies with CIS Benchmark
[FAIL]   - Configuration violates CIS Benchmark
[WARN]   - Check not applicable or warning-level
[INFO]   - Informational only
```

### kubescape (Multi-Framework)
```bash
# Run via phase5-assess
make phase5-assess

# View results
jq '.controls[]' reports/phase5-assessment/TIMESTAMP/kubescape-results.json

# Shows: CIS, NSA-CISA, MITRE ATT&CK, SOC2, Pod Security Standards
```

### trivy-operator (Continuous Scanning)
```bash
# Install
make phase5-trivy-operator-install

# Query findings
make phase5-trivy-operator-query

# Or manually:
kubectl get vulnerabilityreports -A
kubectl get configauditreports -A
kubectl get secretreports -A
kubectl get rbacassessmentreports -A
```

---

## Common Commands

### View Vulnerability Reports
```bash
# Summary across all namespaces
kubectl get vulnerabilityreports -A

# Detailed findings for a pod
kubectl describe vulnerabilityreport -n <namespace> <report-name>

# Raw YAML with all details
kubectl get vulnerabilityreport -n <ns> <name> -o yaml | jq '.report'
```

### View Configuration Audit Reports
```bash
# Summary
kubectl get configauditreports -A

# Details
kubectl describe configauditreport -n <namespace> <report-name>

# Which controls failed
kubectl get configauditreport -n <ns> -o yaml | \
  jq '.report.checks[] | select(.success==false)'
```

### View Secret Exposure Reports
```bash
kubectl get secretreports -A
kubectl describe secretreport -n <ns> <name>
```

### View RBAC Assessment Reports
```bash
kubectl get rbacassessmentreports -A
kubectl describe rbacassessment -n <ns> <name>
```

---

## Interpreting Findings

### Severity Levels
```
CRITICAL   - Must fix immediately
HIGH       - Fix soon (this sprint)
MEDIUM     - Fix in next iteration
LOW        - Address in future
INFO       - Informational only
```

### Common Findings and Fixes

| Finding | Tool | Severity | Fix |
|---------|------|----------|-----|
| Image uses `:latest` tag | trivy-op | MEDIUM | Use specific version: `nginx:1.27-alpine` |
| Running as root | trivy-op | MEDIUM | Add `securityContext.runAsNonRoot: true` |
| No resource limits | trivy-op | MEDIUM | Add `resources.limits` |
| Secret in env var | trivy-op | HIGH | Use volume mount instead |
| CVE in image | trivy-op | CRITICAL/HIGH | Update image to patched version |
| Privileged container | kube-bench/trivy-op | HIGH | Remove `privileged: true` from spec |
| RBAC not configured | kubescape | CRITICAL | Add RBAC RoleBindings |
| Encryption not enabled | kube-bench | HIGH | Recreate cluster with `make phase4-up` |

---

## Remediation Pattern

For each finding:

1. **Understand the risk**
   - Read docs/phase5-assessment-guide.md
   - Check docs/phase5-control-mapping.md

2. **Identify the fix**
   - Review relevant Phase 1-4 documentation
   - Check example policy/manifests

3. **Apply the fix**
   ```bash
   # Edit pod/deployment spec
   kubectl edit pod <name>

   # Or update Kyverno policy
   kubectl apply -f policies/phase-4-secrets/...
   ```

4. **Verify the fix**
   ```bash
   # trivy-operator rescans automatically
   # Wait 30-60 seconds for new report
   kubectl get vulnerabilityreports -n <ns>

   # Should show improvement
   ```

---

## Attack Simulation Tests

### Test 1: RBAC Enforcement
```bash
# Try to access prod secrets without permission
kubectl --as=system:serviceaccount:phase5-tests:attacker \
  get secrets -n prod

# Expected: Forbidden (403)
# Actual: ✅ RBAC blocks it
```

### Test 2: Pod Security
```bash
# Try to deploy privileged container
kubectl apply -f - << 'EOF'
spec:
  securityContext:
    privileged: true
EOF

# Expected: Policy rejection
# Actual: ✅ Kyverno blocks it
```

### Test 3: Network Policies
```bash
# From dev namespace, try to reach default namespace
kubectl -n dev exec pod-name -- wget http://service.default.svc

# Expected: Connection timeout
# Actual: ✅ NetworkPolicy blocks it
```

### Test 4: Secret Policy
```bash
# Try to create secret without 'secret' in name
kubectl create secret generic mydata --from-literal=x=y

# Expected: Policy rejection
# Actual: ✅ Policy requires '-secret' in name
```

---

## Hands-on Validation Tests

### Test Latest Image Tag
```bash
# Deploy with latest tag (bad practice)
kubectl run test-latest --image=nginx:latest

# Wait 30-60 seconds, check findings
kubectl describe vulnerabilityreport -n default pod-test-latest

# Expected: Warning about 'latest' tag, possible CVEs
# Remediate: Update to specific version
kubectl set image deployment/test-latest nginx=nginx:1.27-alpine
```

### Test No Security Context
```bash
# Deploy without security hardening
kubectl apply -f - << 'EOF'
spec:
  containers:
  - name: app
    image: nginx:latest
    # No securityContext!
EOF

# Check findings
kubectl describe configauditreport -n default pod-name

# Expected: Multiple issues (running as root, etc.)
# Remediate: Add securityContext
```

### Test Secrets in Env Vars
```bash
# Create secret, then use in pod env var (BAD!)
kubectl create secret generic db-password --from-literal=password=secret
kubectl apply -f - << 'EOF'
env:
- name: DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: db-password
      key: password
EOF

# Check findings
kubectl get secretreports -n default

# Expected: Secret exposure detected
# Remediate: Use volume mount instead
```

### Test Old Image with CVEs
```bash
# Deploy old version with known CVEs
kubectl run vulnerable --image=nginx:1.19.0

# Wait 2-5 minutes for scan
kubectl describe vulnerabilityreport -n default pod-vulnerable

# Expected: Multiple CVEs (CRITICAL/HIGH)
# Remediate: Update to patched version
kubectl set image pod/vulnerable vulnerable=nginx:1.27-alpine
```

---

## Troubleshooting

### "No vulnerability reports found"
```bash
# Check operator is running
kubectl get pods -n trivy-system

# Check operator logs
kubectl logs -n trivy-system deploy/trivy-operator

# Operator may need 2-5 minutes for initial scan
# Wait and check again
kubectl get vulnerabilityreports -A
```

### "Report shows but I expected different findings"
```bash
# Check trivy database version
trivy version

# Different image versions have different CVEs
# This is expected and normal

# Update trivy-operator
helm upgrade trivy-operator aqua/trivy-operator \
  -n trivy-system
```

### "Can't exec into pod"
```bash
# Some images (like nginx:alpine) don't have shells
# Try a different image:
kubectl run debug --image=busybox -- sleep 3600

# Or install shell:
kubectl exec pod-name -- apk add bash
```

### "Cleanup not working"
```bash
# Force delete namespace
kubectl delete namespace phase5-tests --force --grace-period=0

# Remove trivy-operator
helm uninstall trivy-operator -n trivy-system
kubectl delete namespace trivy-system

# Remove reports
rm -rf reports/phase5-*
```

---

## Report Locations

```bash
reports/phase5-assessment/TIMESTAMP/
├── assessment-report.html      # Visual report (open in browser)
├── kube-bench-results.json     # Raw kube-bench output
├── kubescape-results.json      # Raw kubescape output
├── kube-bench.log              # Kube-bench execution log
├── kubescape.log               # Kubescape execution log
└── assessment.log              # Combined log

reports/phase5-simulation/
└── simulation-results-TIMESTAMP.txt  # Attack test results
```

---

## Documentation Quick Links

| Document | Purpose |
|----------|---------|
| phase5-assessment-guide.md | What each tool does, how to interpret findings |
| phase5-control-mapping.md | How Phases 1-4 controls address findings |
| phase5-trivy-operator-validation.md | Hands-on validation guide |
| PHASE5_IMPLEMENTATION_PLAN.md | Full implementation details |

---

## Next Steps

**After completing Phase 5:**

1. ✅ You understand security assessment tools
2. ✅ You've validated that Phase 1-4 controls work
3. ✅ You've seen continuous monitoring in action

**For production:**

- Use **trivy-operator** for continuous monitoring
- Export findings to monitoring/alerting system
- Set SLAs for fixing CRITICAL/HIGH findings
- Regular image updates and patching
- Automate remediation where possible

---

## Example Full Workflow

```bash
# Start fresh cluster
make cluster-down
make phase4

# Assessment (point-in-time)
make phase5-assess
# → Review reports in reports/phase5-assessment/

# Install continuous monitoring
make phase5-trivy-operator-install
sleep 300  # Wait 5 min for initial scans

# Query and compare
make phase5-trivy-operator-query
# → See how trivy-operator supersedes point-in-time tools

# Validate controls work
make phase5-simulate
# → All 4 tests should pass

# Hands-on learning
make phase5-validate
# → Run scenarios from docs/phase5-trivy-operator-validation.md

# Cleanup
make phase5-reset
```

That's Phase 5! You've completed the full security lab. 🎓

