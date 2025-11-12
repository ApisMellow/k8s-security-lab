# Phase 5: Security Assessment Guide

This guide explains what each assessment tool does, how to interpret findings, and how Phases 1-4 security controls address them.

---

## Part 1: Understanding kube-bench

### What is kube-bench?

**kube-bench** is a security auditing tool that checks whether your Kubernetes cluster complies with the **CIS Kubernetes Benchmark**.

The **CIS (Center for Internet Security) Benchmark** is a standardized set of 100+ security best practices for Kubernetes. It's maintained by security experts and widely used for compliance (PCI-DSS, HIPAA, SOC2, etc.).

### What does it check?

kube-bench evaluates 4 main categories:

#### 1. **Master Node Security** (1.x checks)
- API server configuration (authentication, audit logging, encryption)
- Controller manager security settings
- Scheduler configuration
- etcd security

**Example checks**:
- "Ensure that the --authorization-mode argument includes RBAC"
- "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
- "Ensure that encryption is enabled for all API data"

#### 2. **Worker Node Security** (2.x checks)
- kubelet configuration
- kube-proxy settings
- OS-level security

**Example checks**:
- "Ensure that the --read-only-port argument is set to 0"
- "Ensure that the --event-qps argument is set to 5 or less"
- "Ensure that the --streaming-connection-idle-timeout is not set to 0"

#### 3. **Kubernetes Policies** (3.x-5.x checks)
- RBAC policies
- Pod security policies
- Network policies
- Secret handling

**Example checks**:
- "Ensure that default service accounts are not actively used"
- "Ensure that Kubernetes dashboard is not deployed"
- "Ensure that default NetworkPolicy does not exist in each namespace"

#### 4. **General Security** (various checks)
- Image registry security
- Log monitoring
- Audit logging

### How to read kube-bench output

When you run `make phase5-assess`, kube-bench produces JSON output. Here's how to interpret it:

```json
{
  "section": "1.1 Control Plane Security",
  "pass": 12,
  "fail": 3,
  "warn": 1,
  "info": 0,
  "checks": [
    {
      "id": "1.1.1",
      "description": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
      "status": "PASS",
      "scoring": { "applicable": true }
    },
    {
      "id": "1.2.2",
      "description": "Ensure that the RotateKubeletServerCertificate argument is set to true",
      "status": "FAIL",
      "scoring": { "applicable": true }
    }
  ]
}
```

**What each status means:**

| Status | Meaning | Action |
|--------|---------|--------|
| **PASS** | Configuration matches CIS recommendation | ✅ No action needed |
| **FAIL** | Configuration violates CIS recommendation | ⚠️  Needs remediation |
| **WARN** | Check not applicable or warning-level issue | ℹ️  Review context |
| **INFO** | Informational - just provides info | ℹ️  No action needed |

### Example: Interpreting a FAIL

If you see:
```
[FAIL] 1.4.11 Ensure that the RotateKubeletServerCertificate argument is set to true
```

This means:
- **What failed**: kubelet is not configured to automatically rotate its server certificates
- **Why it matters**: Manual certificate rotation is error-prone; automatic rotation prevents certificate expiration issues
- **How to fix**: Configure kubelet with `--rotate-server-certificates=true`
- **Phase 1 connection**: This is part of cluster infrastructure hardening

### Limitations of kube-bench

- ❌ Only checks cluster configuration, not actual behavior
- ❌ Doesn't find vulnerabilities in container images
- ❌ Doesn't detect secrets exposure
- ❌ Point-in-time check (must re-run manually)
- ❌ No context about threat models
- ✅ Very comprehensive on CIS configuration checks
- ✅ Fast execution (usually < 5 minutes)

---

## Part 2: Understanding kubescape

### What is kubescape?

**kubescape** is a multi-framework security assessment tool. Instead of checking a single standard (CIS), it evaluates your cluster against multiple security frameworks simultaneously.

### Supported Frameworks

#### 1. **CIS Kubernetes Benchmark**
Same checks as kube-bench, but kubescape groups them by framework.

#### 2. **NSA-CISA Hardening Guidance**
The U.S. National Security Agency and Cybersecurity & Infrastructure Security Agency published hardening guidelines. kubescape checks compliance with their recommendations.

**Example NSA recommendations**:
- Restrict access to the API server
- Encrypt data in transit and at rest
- Use strong authentication and authorization

#### 3. **MITRE ATT&CK Framework**
MITRE ATT&CK is a comprehensive matrix of real-world attack techniques used by adversaries.

kubescape maps security controls to MITRE tactics:
- **T1018**: Discovery (finding resources)
- **T1021**: Lateral Movement (moving between systems)
- **T1040**: Traffic Sniffing (capturing network traffic)
- etc.

**Example**: "Ensure RBAC is configured" prevents T1021 (Lateral Movement)

#### 4. **SOC 2 Compliance**
SOC 2 is a compliance framework for service providers. kubescape checks relevant security controls.

#### 5. **Pod Security Standards**
Kubernetes' own Pod Security Standards (replacement for Pod Security Policies).

### How kubescape differs from kube-bench

| Aspect | kube-bench | kubescape |
|--------|-----------|-----------|
| **Primary focus** | CIS only | Multiple frameworks |
| **Depth** | Very detailed (100+ checks) | Broader (fewer per framework) |
| **Context** | Just pass/fail | Links to threat models & tactics |
| **Frameworks** | 1 (CIS) | 5+ (CIS, NSA, MITRE, SOC2, etc.) |
| **Learning value** | "What's the CIS recommendation?" | "Why does this control matter?" |
| **Best for** | Detailed CIS compliance audits | Understanding why controls exist |

### How to read kubescape output

kubescape groups findings by framework:

```json
{
  "control": "Restrict access to the admin account",
  "framework": "NSA",
  "severity": "CRITICAL",
  "compliant": 0,
  "total": 5,
  "description": "Ensure that the admin account is restricted",
  "remediation": "Create RBAC roles with least privilege"
}
```

**What it tells you:**
- Control: What to fix
- Framework: Which standard requires it (NSA, MITRE, etc.)
- Severity: How critical
- Compliant: How many resources pass (0/5 = none pass)
- Remediation: How to fix it

### Example: Control Mapped to Multiple Frameworks

One control might appear in multiple frameworks:

```
Control: "Restrict privileged containers"
├─ CIS: Rule 5.2.1
├─ NSA: Security Control 1.3
├─ MITRE: T1054 (Lateral Movement prevention)
└─ Pod Security: Baseline/Restricted
```

This shows the control is important across multiple standards and threat models.

### Limitations of kubescape

- ❌ Less detailed than kube-bench on CIS checks
- ❌ Point-in-time assessment (must re-run manually)
- ❌ Limited image vulnerability scanning
- ❌ Limited secret detection
- ✅ Multiple frameworks (broader understanding)
- ✅ Threat model context (MITRE ATT&CK)
- ✅ Better remediation guidance
- ✅ Helps understand why controls matter

---

## Part 3: Understanding trivy-operator

### What is trivy-operator?

**trivy-operator** is a Kubernetes operator that continuously scans your cluster for security issues. Unlike kube-bench and kubescape (which you run manually), trivy-operator runs continuously and automatically scans new workloads as they're created.

### What does it scan?

trivy-operator performs multiple types of scans:

#### 1. **Vulnerability Scanning (VulnerabilityReports)**
Scans container images for known vulnerabilities (CVEs).

**What it checks**:
- Operating system packages with security vulnerabilities
- Application dependencies with known CVEs
- SBOM (Software Bill of Materials) generation

**Example finding**:
```
CVE-2021-4034 (CRITICAL)
- Affected: polkit (authentication system)
- Severity: CRITICAL
- Action: Update polkit to version X.X.X
```

#### 2. **Configuration Audit (ConfigAuditReports)**
Scans pod specifications against security best practices (including CIS benchmarks).

**What it checks**:
- Pod security context (runAsUser, allowPrivilegeEscalation, etc.)
- Container image policies (latest tags, etc.)
- Resource limits
- Health checks
- Security best practices

**Example finding**:
```
Pod running without security context
- Issue: Container runs as root
- Severity: MEDIUM
- Fix: Add securityContext.runAsNonRoot: true
```

#### 3. **Secret Detection (SecretReports)**
Scans for secrets exposed in unusual places.

**What it checks**:
- Secrets in environment variables
- Secrets in container logs
- Plaintext secrets in configs
- AWS keys, API tokens, etc.

**Example finding**:
```
Secret detected in environment variable
- Type: DATABASE_PASSWORD
- Severity: HIGH
- Risk: Visible in kubectl describe, logs, metrics
- Fix: Use volume mounts instead
```

#### 4. **RBAC Assessment (RBACAssessmentReports)**
Evaluates role-based access control configurations.

**What it checks**:
- Overly permissive RBAC rules
- Service accounts with unnecessary permissions
- Wildcards in RBAC rules

#### 5. **Infrastructure Component Scanning**
Scans Kubernetes infrastructure components themselves.

**What it checks**:
- API server security
- etcd security
- Scheduler configuration
- Controller manager security

### How trivy-operator differs from kube-bench/kubescape

| Aspect | kube-bench | kubescape | trivy-operator |
|--------|-----------|-----------|----------------|
| **Scope** | Cluster config only | Multi-framework posture | Everything |
| **Image CVEs** | No | Limited | Yes (full DB) |
| **Secrets** | No | No | Yes |
| **Timing** | Manual/on-demand | Manual/on-demand | Continuous |
| **Trigger** | User runs command | User runs command | Automatic on changes |
| **Results storage** | JSON/text | JSON/text | Kubernetes CRDs |
| **Query method** | Download/parse reports | Download/parse reports | kubectl get/describe |
| **Production ready** | Better for audits | Better for audits | Best for monitoring |

### How to query trivy-operator results

trivy-operator stores findings as Kubernetes Custom Resource Definitions (CRDs):

```bash
# View vulnerability reports
kubectl get vulnerabilityreports -A
kubectl describe vulnerabilityreport -n <ns> <name>

# View configuration audits
kubectl get configauditreports -A
kubectl describe configauditreport -n <ns> <name>

# View secret detection
kubectl get secretreports -A

# View RBAC assessments
kubectl get rbacassessmentreports -A
```

### Key Advantage: Kubernetes-Native

Because trivy-operator stores results as Kubernetes CRDs, you can:
- Query with standard `kubectl` commands
- Integrate with Kubernetes controllers
- Set up alerts based on findings
- Export results to monitoring systems
- Use Kubernetes RBAC to control who sees what

### Limitations of trivy-operator

- ⚠️ Takes 2-5 minutes for initial cluster scan
- ⚠️ Requires cluster resources to run scans
- ✅ Comprehensive (CVEs + config + secrets + RBAC)
- ✅ Continuous monitoring
- ✅ Kubernetes-native results
- ✅ Automatic on workload changes
- ✅ Includes CIS benchmarks
- ✅ Production-ready

---

## Part 4: How Phases 1-4 Address Assessment Findings

### Phase 1: RBAC & Audit Logging

**Findings this addresses:**
- "No RBAC configured" (kube-bench, kubescape, trivy-operator)
- "Default service accounts have too many permissions" (trivy-operator RBAC)
- "API access is unrestricted" (kubescape, trivy-operator)

**How Phase 1 controls work:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]  # ✅ Only read access to specific resources
```

**Assessment evidence:**
- kube-bench: "Rules 1.10.x" (RBAC enforcement)
- kubescape: "NSA: Restrict access to the admin account"
- trivy-operator: RBACAssessmentReports show limited permissions

---

### Phase 2: Pod Security Policies

**Findings this addresses:**
- "Privileged containers allowed" (kube-bench, kubescape, trivy-operator)
- "Running as root" (kubescape, trivy-operator)
- "Latest image tags used" (trivy-operator)
- "No resource limits" (trivy-operator)

**How Phase 2 controls work:**
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
              privileged: false  # ✅ Blocks privileged pods
```

**Assessment evidence:**
- kube-bench: "Rule 2.2.1" (Pod security policies)
- kubescape: "CIS: Restrict privileged containers"
- trivy-operator: ConfigAuditReports show compliant securityContext

---

### Phase 3: Network Policies

**Findings this addresses:**
- "Cross-namespace traffic not restricted" (kubescape, trivy-operator)
- "No network segmentation" (kubescape)
- "Default deny rules not applied" (trivy-operator)

**How Phase 3 controls work:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
  - Ingress
  # ✅ No 'ingress' rules = deny all ingress
```

**Assessment evidence:**
- kubescape: "NSA: Restrict network connectivity"
- trivy-operator: Network policy checks show isolation

---

### Phase 4: Secrets Encryption & Hygiene

**Findings this addresses:**
- "Secrets not encrypted at rest" (kube-bench rule 1.4.10)
- "Secrets in environment variables" (trivy-operator secret detection, Kyverno policy)
- "CVEs in container images" (trivy-operator vulnerability scanning)
- "Old image versions with known vulnerabilities" (trivy-operator)

**How Phase 4 controls work:**

1. **Encryption at rest**:
```bash
# Cluster created with:
--secrets-encryption=aescbc  # ✅ Encrypts all secrets in etcd
```

2. **Secret naming policy**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-secret-names
spec:
  validationFailureAction: enforce
  rules:
  - name: secret-name
    validate:
      pattern:
        metadata:
          name: "*secret*"  # ✅ Forces 'secret' in name
```

3. **Image vulnerability scanning**:
```
CVE-2021-4034 found in nginx:1.19.0
→ Update to nginx:1.27-alpine
→ Re-scan shows vulnerability fixed
```

**Assessment evidence:**
- kube-bench: "Rule 1.4.10" (Secrets encryption)
- kubescape: "NSA: Encrypt sensitive data"
- trivy-operator: VulnerabilityReports, SecretReports, ConfigAuditReports

---

## Part 5: Complete Control Mapping

### Summary Table

| Finding Category | kube-bench | kubescape | trivy-operator | Phase | Control |
|-----------------|-----------|-----------|----------------|-------|---------|
| **RBAC Missing** | ❌ | ✅ | ✅ | 1 | RoleBinding |
| **Unrestricted API** | ✅ | ✅ | ✅ | 1 | RBAC enforcement |
| **Privileged Containers** | ✅ | ✅ | ✅ | 2 | disallow-privileged |
| **Running as Root** | ❌ | ✅ | ✅ | 2 | runAsNonRoot |
| **No Network Isolation** | ❌ | ✅ | ✅ | 3 | NetworkPolicy |
| **Secrets Unencrypted** | ✅ | ✅ | ❌* | 4 | etcd encryption |
| **CVEs in Images** | ❌ | ❌ | ✅ | 4 | Image scanning |
| **Secrets in Env Vars** | ❌ | ❌ | ✅ | 4 | disallow-env-secrets |

*trivy-operator can't directly check encryption, but can verify encrypted secrets exist

---

## Summary: Which Tool to Use When

### For Learning
1. Start with **kube-bench** to see CIS Benchmark checklist
2. Use **kubescape** to understand frameworks and threat models
3. Deploy **trivy-operator** to see continuous monitoring

### For Compliance Audits
- Use **kube-bench** (gold standard for CIS compliance)
- Use **kubescape** for multi-framework compliance

### For Production Monitoring
- Use **trivy-operator** (continuous, automatic, comprehensive)
- Keep kube-bench/kubescape for periodic formal audits

### For Vulnerability Management
- Use **trivy-operator** (tracks CVEs continuously)
- Run `make phase4-scan` with Trivy for manifest scanning

