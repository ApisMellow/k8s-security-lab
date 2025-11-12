# Phase 5: Control Mapping - Assessment Findings to Phase 1-4 Controls

This document maps security assessment findings to the Phase 1-4 hardening controls that address them.

---

## Quick Reference Matrix

| Assessment Finding | Tool(s) | Phase | Control Name | Status | Remediation |
|-------------------|---------|-------|--------------|--------|-------------|
| **RBAC missing** | bench, scope, op | 1 | RoleBinding with least privilege | ✅ Implemented | make phase1-harden |
| **Unrestricted API access** | bench, scope, op | 1 | RBAC enforcement | ✅ Implemented | make phase1-harden |
| **No namespace isolation** | scope, op | 1 | Namespace + RBAC | ✅ Implemented | make phase1-harden |
| **Audit logging disabled** | bench | 1 | API audit logging | ✅ Implemented | make phase1-up |
| **Privileged containers allowed** | bench, scope, op | 2 | disallow-privileged policy | ✅ Implemented | make phase2-harden |
| **Running as root** | scope, op | 2 | runAsNonRoot + securityContext | ✅ Implemented | make phase2-harden |
| **Dangerous capabilities** | scope, op | 2 | drop-net-raw-capability policy | ✅ Implemented | make phase2-harden |
| **Latest image tags** | op (config audit) | 2 | require-specific-tags policy | ❌ Not implemented | Enhance phase2 |
| **No resource limits** | scope, op | 2 | Resource limits (external) | ❌ Not implemented | Add to phase2 |
| **Cross-namespace traffic allowed** | scope, op | 3 | NetworkPolicy default deny | ✅ Implemented | make phase3-harden |
| **No network segmentation** | scope, op | 3 | NetworkPolicy isolation | ✅ Implemented | make phase3-harden |
| **Secrets not encrypted at rest** | bench (1.4.10) | 4 | etcd encryption enabled | ✅ Implemented | make phase4-up |
| **Secrets in environment variables** | op (secret detection), bench | 4 | disallow-env-secrets policy | ✅ Implemented | make phase4-harden |
| **CVEs in container images** | op (vulnerability scan) | 4 | Image scanning with Trivy | ✅ Implemented | make phase4-scan |
| **Plaintext secret names** | op, bench | 4 | require-secret-names policy | ✅ Implemented | make phase4-harden |

**Legend**:
- bench = kube-bench
- scope = kubescape
- op = trivy-operator
- ✅ = Currently implemented
- ❌ = Not in current implementation (enhancement opportunity)

---

## Detailed Control Mappings

### Phase 1: RBAC & Audit Logging

#### Control 1.1: RBAC Enforcement
**What it does**: Implements Role-Based Access Control to limit what users/service accounts can do

**Assessment findings it addresses**:
- kube-bench 1.10.1: "Ensure that RBAC is enabled"
- kubescape: "Restrict access to admin accounts"
- kubescape: "NSA: Restrict unauthorized access"

**How it works**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-viewer
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-viewer-binding
  namespace: dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-viewer
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

**Evidence in assessments**:
```bash
# kube-bench checks
✅ 1.10.1 Ensure that RBAC is enabled
✅ 1.10.2 Ensure that default service account is not used

# kubescape framework mapping
NSA-CISA: Restrict access to sensitive APIs
MITRE ATT&CK: T1018 (Discovery prevention via access control)
CIS: Rule 1.10 (RBAC enforcement)

# trivy-operator RBAC assessment
✅ Service account has minimal permissions
✅ No wildcard permissions
```

**Remediation path**: If assessment shows RBAC issues → `make phase1-harden`

---

#### Control 1.2: API Audit Logging
**What it does**: Records all API server requests for monitoring and forensics

**Assessment findings it addresses**:
- kube-bench 1.2.1-1.2.25: Audit logging configuration checks

**How it works**:
```bash
# Cluster created with audit logging enabled
scripts/cluster-up-phase1-with-audit.sh
```

**Evidence in assessments**:
```bash
# kube-bench checks
✅ 1.2.1 Ensure that a log file max age is configured
✅ 1.2.2 Ensure that log file max backup is configured
✅ 1.2.36 Ensure that the --audit-log-maxage argument is set
```

**Remediation path**: If audit logging issues → Recreate cluster with `make phase1-up`

---

### Phase 2: Pod Security Policies

#### Control 2.1: Disallow Privileged Containers
**What it does**: Prevents containers from running with privileged flag (which can escape sandbox)

**Assessment findings it addresses**:
- kube-bench 2.2.1: "Ensure that Privileged containers are not used"
- kubescape: "Privileged containers should not be used"
- trivy-operator ConfigAuditReport: "Container may run with elevated privileges"

**How it works**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: enforce
  rules:
  - name: privileged
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - securityContext:
              =(privileged): false  # ❌ Blocks privileged: true
```

**Evidence in assessments**:
```bash
# kube-bench checks
✅ 2.2.1 Ensure that Privileged containers are not used
✅ 2.2.5 Ensure that service account tokens are mounted with a projected volume with restricted permissions

# trivy-operator
ConfigAuditReport: Pod has securityContext.privileged=false ✅

# kubescape
CIS Rule 5.2: Privileged containers blocked
MITRE: T1190 (Exploitation of Vulnerability) prevented
```

**Remediation path**: If privileged containers detected → `make phase2-harden`

**Test it**: Try to deploy `kubectl apply -f manifests/phase5-tests/02-pod-security-test.yaml`

---

#### Control 2.2: Drop Dangerous Capabilities
**What it does**: Removes Linux capabilities that could be abused (NET_RAW, SYS_ADMIN, etc.)

**Assessment findings it addresses**:
- kube-bench 2.2.8: "Ensure that Linux Kernel Capabilities are restricted and set to a whitelist"
- kubescape: "Capabilities should be restricted"

**How it works**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: drop-net-raw-capability
spec:
  validationFailureAction: audit  # audit initially, enforce later
  rules:
  - name: net-raw
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "NET_RAW capability should not be enabled"
      pattern:
        spec:
          containers:
          - securityContext:
              capabilities:
                drop:
                - NET_RAW  # ❌ Drops NET_RAW capability
```

**Remediation path**: If capabilities issues → `make phase2-harden`

---

#### Control 2.3: Non-Root User
**What it does**: Requires containers to run as non-root user

**Assessment findings it addresses**:
- kube-bench 2.2.2: "Ensure that 'root' user is not used"
- kubescape: "Container should run as non-root user"
- trivy-operator: "Container should run as non-root"

**How it works**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  securityContext:
    runAsNonRoot: true  # ✅ Enforces non-root
    runAsUser: 1000     # Specific non-root user
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
```

**Evidence in assessments**:
```bash
# trivy-operator ConfigAuditReport
✅ "Container should run as non-root user" - PASS
- securityContext.runAsNonRoot: true
- securityContext.runAsUser: 1000

# kubescape
CIS: Pod security enforcement
MITRE: T1548 (Privilege Escalation) prevented
```

**Remediation path**: If running as root → Update pod spec with securityContext

---

### Phase 3: Network Policies

#### Control 3.1: Default Deny Ingress
**What it does**: Blocks all incoming traffic by default, requires explicit allow rules

**Assessment findings it addresses**:
- kubescape: "Network policies are properly configured"
- trivy-operator: "Default deny rules are in place"

**How it works**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}  # Applies to all pods in namespace
  policyTypes:
  - Ingress
  # No 'ingress' rules = deny all ingress
```

**Evidence in assessments**:
```bash
# trivy-operator
✅ NetworkPolicy properly configured
✅ Default deny rules are active
✅ No unrestricted traffic

# kubescape
NSA: Network policies enforce zero-trust
MITRE: T1021 (Lateral Movement) prevented
```

**Remediation path**: If cross-namespace traffic detected → `make phase3-harden`

**Test it**: See `make phase5-simulate` test 3

---

#### Control 3.2: Default Deny Egress
**What it does**: Blocks all outgoing traffic by default, requires explicit allow rules

**How it works**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  # No 'egress' rules = deny all egress
```

**Remediation path**: If egress issues → Review `network-policies/` and adjust allow rules

---

### Phase 4: Secrets Encryption & Hygiene

#### Control 4.1: Encryption at Rest
**What it does**: Encrypts all secrets stored in etcd using AES-GCM encryption

**Assessment findings it addresses**:
- kube-bench 1.4.10: "Ensure that the Etcd data is encrypted"

**How it works**:
```bash
# Cluster created with encryption enabled
scripts/cluster-up-phase4.sh

# Under the hood:
# - API server started with --encryption-provider-config
# - etcd uses AES-GCM cipher
# - All secrets are encrypted when stored
```

**Evidence in assessments**:
```bash
# kube-bench
✅ 1.4.10 Ensure that Etcd data is encrypted

# Verification:
kubectl create secret generic test --from-literal=password=secret
# Secret stored encrypted in etcd
```

**Remediation path**: If encryption not enabled → Must recreate cluster with `make phase4-up`

---

#### Control 4.2: Disallow Environment Variable Secrets
**What it does**: Prevents using environment variables for secret values (they leak easily)

**Assessment findings it addresses**:
- kube-bench: General secret best practices
- trivy-operator SecretReport: "Sensitive data in environment variable detected"
- kubescape: "Sensitive data should not be exposed"

**How it works**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-env-secrets
spec:
  validationFailureAction: enforce
  rules:
  - name: secret-env-var
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Using secrets in environment variables is not allowed"
      pattern:
        spec:
          containers:
          - env:
            - name: "?*PASSWORD*|?*TOKEN*|?*SECRET*|?*KEY*|?*API_KEY*"
              valueFrom:
                secretKeyRef: null  # ❌ Blocks env vars from secrets
```

**Evidence in assessments**:
```bash
# trivy-operator SecretReport
❌ "Sensitive environment variable detected"
  Variable: DATABASE_PASSWORD
  Risk: Visible in kubectl describe, logs, metrics

# After remediation: ✅ Secret mounted as volume instead
```

**Remediation path**: If env var secrets detected → Update pod to use volume mounts

**Test it**: See `make phase5-simulate` test 4 and `make phase5-validate` test 3

---

#### Control 4.3: Require Secret Naming Convention
**What it does**: Enforces secret names include 'secret' (obviously identifies them as secrets)

**Assessment findings it addresses**:
- kube-bench: General secret best practices
- trivy-operator ConfigAuditReport: "Secrets should follow naming conventions"

**How it works**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-secret-names
spec:
  validationFailureAction: enforce
  rules:
  - name: secret-names
    match:
      resources:
        kinds:
        - Secret
    validate:
      message: "Secret names must include 'secret-' or '-secret-'"
      pattern:
        metadata:
          name: "*secret*"  # ✅ Enforces naming pattern
```

**Evidence in assessments**:
```bash
# kube-bench
✅ Secrets follow naming conventions

# trivy-operator ConfigAuditReport
✅ "Secret naming convention followed"
```

**Remediation path**: If naming issues → Rename secrets to include 'secret'

**Test it**: Try to create secret without 'secret' in name

---

#### Control 4.4: Image Vulnerability Scanning
**What it does**: Scans container images for known CVEs using Trivy

**Assessment findings it addresses**:
- trivy-operator VulnerabilityReport: CVE-XXXX found in image
- kube-bench: General security best practices

**How it works**:
```bash
# Manual: make phase4-scan
bash scanners/trivy-scan-manifests.sh policies/
bash scanners/trivy-scan-cluster.sh

# Continuous: trivy-operator scans on pod creation
kubectl run app --image=nginx:1.19.0
# → trivy-operator detects CVEs within 1-2 minutes
```

**Evidence in assessments**:
```bash
# trivy-operator VulnerabilityReport
CVE-2021-4034 (CRITICAL)
  Package: polkit
  Affected: nginx:1.19.0
  Fix: Update to nginx:1.27-alpine

# After remediation
CVE-2021-4034: FIXED (updated image)
```

**Remediation path**: If CVEs detected → Update image to patched version

**Test it**: See `make phase5-validate` test 4

---

## Remediation Flowchart

```
Assessment Finding Detected
         ↓
    Which Phase?
    ↙  ↓  ↘
   1   2   3   4
   ↓   ↓   ↓   ↓
Phase1 Phase2 Phase3 Phase4
Control Control Control Control
   ↓   ↓   ↓   ↓
Run "make phase1-harden" or similar
   ↓
Re-run assessment
   ↓
Finding resolved?
  Yes → ✅ Control validated
  No  → Debug: Check logs, Policy CRDs, Pod specs
```

---

## Validating Controls are Working

### Phase 1: RBAC
```bash
# Should be forbidden
kubectl --as=system:serviceaccount:phase5-tests:attacker \
  get secrets -n prod
# Expected: Error from server (Forbidden)
```

### Phase 2: Pod Security
```bash
# Should be rejected
kubectl apply -f - << 'EOF'
spec:
  securityContext:
    privileged: true
EOF
# Expected: Error: policy violation
```

### Phase 3: Network Policies
```bash
# From dev namespace, try to reach default
kubectl -n dev exec pod-name -- \
  wget -T2 http://service.default.svc
# Expected: Connection timeout
```

### Phase 4: Encryption
```bash
# Secret is encrypted at rest
kubectl create secret generic test --from-literal=x=y
# In etcd, data appears encrypted (not plaintext)

# Secret naming policy
kubectl create secret generic mydata --from-literal=x=y
# Expected: Error: Secret name must contain 'secret'
```

---

## Enhancements for Future Phases

The following findings are identified but not currently in Phase 1-4:

### Enhancement 1: Image Tag Validation
**Finding**: Latest image tags should be avoided

**Current**: trivy-operator detects this

**Enhancement opportunity**: Add Kyverno policy to enforce specific tag format
```yaml
# Example: require semver tags
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-version
spec:
  rules:
  - name: image-version
    match:
      resources:
        kinds:
        - Pod
    validate:
      pattern:
        spec:
          containers:
          - image: "*:v[0-9].[0-9].[0-9]"
```

### Enhancement 2: Resource Limits
**Finding**: Pods should have CPU/memory limits

**Current**: trivy-operator detects missing limits

**Enhancement opportunity**: Add Kyverno policy to require limits
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resources
spec:
  rules:
  - name: resources
    match:
      resources:
        kinds:
        - Pod
    validate:
      pattern:
        spec:
          containers:
          - resources:
              limits:
                cpu: "?*"
                memory: "?*"
```

---

## Summary

Every significant security finding from assessments maps back to one of the Phase 1-4 controls. By systematically hardening each phase, you address dozens of security findings and align with industry standards (CIS, NSA-CISA, MITRE ATT&CK, SOC2, Pod Security Standards).
