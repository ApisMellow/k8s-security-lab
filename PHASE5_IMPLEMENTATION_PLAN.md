# Phase 5: Assessment & Attack Simulation - Complete Implementation Plan

## Overview

Phase 5 validates Phases 1-4 security controls through three integrated components:

1. **Point-in-time Assessment** (kube-bench + kubescape) - See what a compliance audit looks like
2. **Continuous Monitoring** (trivy-operator) - Understand automated ongoing security scanning
3. **Attack Simulation** - Verify controls actually prevent attacks
4. **Hands-on Validation** - Make changes, watch trivy-operator detect them, fix them

Total estimated effort: 12-16 hours (includes thorough documentation and validation)

---

## Tool Architecture & Capabilities

### kube-bench: CIS Benchmark Compliance Auditing
- **100+ specific checks** against CIS Kubernetes Benchmark v1.23
- **Very precise**: Checks exact kubelet flags, API server configuration
- **Output**: Pass/fail checklist with severity
- **Learning**: Shows what the CIS standard actually requires
- **Installation**: Docker container (isolated, no devbox pollution)

### kubescape: Multi-framework Posture Assessment
- **Multiple frameworks**: CIS, NSA-CISA, MITRE ATT&CK, SOC 2
- **Broader context**: Same controls mapped to different threat models
- **Output**: Posture score, failed controls, remediation guidance
- **Learning**: Why controls matter, not just compliance checklist
- **Installation**: `nixpkgs#kubescape` (add to devbox.json)

### trivy-operator: Continuous Kubernetes-Native Scanning
- **Comprehensive**: Image vulnerabilities + config audits (CIS) + secrets + RBAC + infrastructure
- **Automated**: Scans trigger on workload changes
- **Kubernetes-native**: Results stored as CRDs, queryable via kubectl
- **Output**: VulnerabilityReports, ConfigAuditReports, SecretReports, RBACAssessmentReports
- **Learning**: How operators extend Kubernetes, continuous monitoring pattern
- **Installation**: Helm chart (kubernetes/helm already in devbox)

### Workflow Logic

```
Phase 5 progression:
├─ Point-in-time assessment (kube-bench)
│  └─ User: "So CIS Benchmark requires X, Y, Z checks"
├─ Multi-framework assessment (kubescape)
│  └─ User: "These same controls appear in NSA-CISA, MITRE, etc."
├─ Install continuous monitoring (trivy-operator)
│  └─ User: "Now it automatically scans and keeps results"
├─ Query trivy-operator results (kubectl)
│  └─ User: "CIS checks are here as CRDs, plus image vulns, secrets"
├─ Hands-on validation test 1 (deploy insecure workload)
│  └─ User: "Trivy-operator catches it immediately"
└─ Hands-on validation test 2 (introduce secret in logs)
   └─ User: "Trivy-operator detects it, I remediate"
```

---

# Implementation Tasks

## Task 0: Update devbox.json for Phase 5 Dependencies

**Objective**: Add kubescape to devbox.json, document trivy-operator Helm dependency

**Acceptance Criteria**:
- kubescape available via `which kubescape` in devbox shell
- Helm already available (kubernetes-helm in current devbox.json)
- Python available for trivy-operator Python dependencies (if any)
- All changes backward-compatible

**Steps**:

1. Add kubescape to packages list
   ```json
   "nixpkgs#kubescape"
   ```

2. Document trivy-operator requirements in comment
   - Helm chart installation (helm already available)
   - Kubernetes cluster with 2GB+ memory
   - kubectl access

3. Lock file will update on next `devbox update`

**Files Modified**:
- `devbox.json` - add kubescape package

---

## Task 1: Create Assessment Orchestrator Script

**Objective**: Create `scripts/phase5-assess.sh` - Run kube-bench + kubescape sequentially, generate unified report

**Acceptance Criteria**:
- Validates cluster is running
- Runs kube-bench in Docker container
- Runs kubescape (binary from devbox)
- Generates timestamped reports in `reports/phase5-assessment/`
- Clear console output showing findings summary
- Takes ~8 minutes total

**Detailed Steps**:

1. Create script skeleton
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail

   TIMESTAMP=$(date +%Y%m%d-%H%M%S)
   REPORT_DIR="reports/phase5-assessment/${TIMESTAMP}"
   LOG_FILE="${REPORT_DIR}/assessment.log"

   mkdir -p "$REPORT_DIR"
   ```

2. Validate cluster is running
   ```bash
   check_cluster_running() {
     kubectl cluster-info &>/dev/null || {
       echo "[ERROR] Cluster not running. Run: make phase4-up"
       exit 1
     }
   }
   ```

3. Run kube-bench via Docker
   ```bash
   run_kube_bench() {
     echo "[INFO] Running kube-bench (CIS Benchmark)..."

     docker run --rm \
       --pid=host \
       -v /etc:/etc:ro \
       -v /lib:/lib:ro \
       -v /usr:/usr:ro \
       -v /sys:/sys:ro \
       -v /var:/var:ro \
       -v /opt:/opt:ro \
       aquasec/kube-bench:latest run \
       --json > "${REPORT_DIR}/kube-bench-results.json" 2>"${LOG_FILE}.bench"

     # Parse and display summary
     local passed=$(jq '[.Results[]? | select(.status=="PASS") | .checks[]?] | length' "${REPORT_DIR}/kube-bench-results.json")
     local failed=$(jq '[.Results[]? | select(.status=="FAIL") | .checks[]?] | length' "${REPORT_DIR}/kube-bench-results.json")

     echo "✅ kube-bench: ${passed} passed, ${failed} failed"
   }
   ```

4. Run kubescape
   ```bash
   run_kubescape() {
     echo "[INFO] Running kubescape (Multi-framework posture)..."

     kubescape scan framework nsa cis \
       --format json \
       --output "${REPORT_DIR}/kubescape-results.json" \
       2>>"${LOG_FILE}.scope"

     # Parse and display summary
     local score=$(jq '.score // 0' "${REPORT_DIR}/kubescape-results.json")
     echo "✅ kubescape: Posture score ${score}%"
   }
   ```

5. Generate unified HTML report
   ```bash
   generate_report() {
     cat > "${REPORT_DIR}/assessment-report.html" << 'EOF'
   <!DOCTYPE html>
   <html>
   <head><title>Phase 5 Assessment Report</title></head>
   <body>
   <h1>Phase 5: Point-in-Time Security Assessment</h1>
   <p>Generated: {{TIMESTAMP}}</p>
   <h2>kube-bench (CIS Benchmark Compliance)</h2>
   <pre>{{KUBE_BENCH_SUMMARY}}</pre>
   <h2>kubescape (Multi-framework Posture)</h2>
   <pre>{{KUBESCAPE_SUMMARY}}</pre>
   <h2>Next Step</h2>
   <p>Run: make phase5-trivy-operator-install</p>
   </body>
   </html>
   EOF
   }
   ```

6. Display completion message
   ```bash
   echo ""
   echo "✅ Assessment Complete"
   echo "📊 Reports saved to: ${REPORT_DIR}/"
   echo "📝 View HTML report: open ${REPORT_DIR}/assessment-report.html"
   echo ""
   echo "Next: Install continuous monitoring with trivy-operator"
   echo "  Run: make phase5-trivy-operator-install"
   ```

**Files Created**:
- `scripts/phase5-assess.sh`

---

## Task 2: Create Trivy-Operator Installation Script

**Objective**: Create `scripts/phase5-trivy-operator-install.sh` - Deploy trivy-operator via Helm, verify installation

**Acceptance Criteria**:
- Validates Helm is installed
- Adds Aqua Security Helm repo
- Deploys trivy-operator to `trivy-system` namespace
- Waits for operator pod to be ready
- Provides guidance on querying results
- Takes ~5 minutes

**Detailed Steps**:

1. Validate prerequisites
   ```bash
   check_helm_installed() {
     command -v helm >/dev/null || {
       echo "[ERROR] Helm not found. Ensure: devbox shell"
       exit 1
     }
   }

   check_cluster_running() {
     kubectl cluster-info &>/dev/null || {
       echo "[ERROR] Cluster not running"
       exit 1
     }
   }
   ```

2. Add Aqua Security Helm repo
   ```bash
   helm repo add aqua https://aquasecurity.github.io/helm-charts/
   helm repo update
   ```

3. Create trivy-system namespace
   ```bash
   kubectl create namespace trivy-system --dry-run=client -o yaml | kubectl apply -f -
   ```

4. Deploy trivy-operator
   ```bash
   helm install trivy-operator aqua/trivy-operator \
     --namespace trivy-system \
     --create-namespace \
     --set="trivyOperator.scanJobsInNamespaces=dev,prod,default" \
     --wait \
     --timeout 5m
   ```

5. Verify installation
   ```bash
   kubectl wait --for=condition=ready pod \
     -l app.kubernetes.io/name=trivy-operator \
     -n trivy-system \
     --timeout=300s

   echo "✅ Trivy-operator deployed successfully"
   ```

6. Provide usage guidance
   ```bash
   cat << 'EOF'
   📊 Trivy-operator is now running and scanning your cluster

   To view vulnerabilities:
     kubectl get vulnerabilityreports -A
     kubectl get vulnerabilityreports -A -o json | jq '.items[0]'

   To view configuration audits:
     kubectl get configauditreports -A
     kubectl describe configauditreport -n <namespace> <report-name>

   To view secrets detection:
     kubectl get secretreports -A

   The operator will continuously scan workloads as they are created.
   EOF
   ```

**Files Created**:
- `scripts/phase5-trivy-operator-install.sh`

---

## Task 3: Create Trivy-Operator Query Script

**Objective**: Create `scripts/phase5-trivy-operator-query.sh` - Display trivy-operator findings in readable format

**Acceptance Criteria**:
- Waits for initial scan to complete (polls for reports)
- Shows vulnerability reports grouped by namespace
- Shows configuration audit reports
- Compares findings to kube-bench/kubescape
- Shows remediation suggestions
- Takes ~2 minutes

**Detailed Steps**:

1. Wait for initial scans to complete
   ```bash
   wait_for_reports() {
     echo "[INFO] Waiting for trivy-operator to complete initial scans..."

     for i in {1..30}; do
       count=$(kubectl get vulnerabilityreports -A 2>/dev/null | wc -l)
       if [ "$count" -gt 1 ]; then
         echo "✅ Found reports (${count} total)"
         return 0
       fi
       echo "  Waiting... (${i}/30)"
       sleep 10
     done

     echo "[WARN] No reports found yet; operator may still be scanning"
   }
   ```

2. Display vulnerability reports
   ```bash
   show_vulnerabilities() {
     echo ""
     echo "=== VULNERABILITY REPORTS ==="
     kubectl get vulnerabilityreports -A -o custom-columns=\
       NAMESPACE:.metadata.namespace,\
       RESOURCE:.metadata.ownerReferences[0].name,\
       CRITICAL:.report.summary.criticalCount,\
       HIGH:.report.summary.highCount,\
       MEDIUM:.report.summary.mediumCount
   }
   ```

3. Display configuration audit reports
   ```bash
   show_config_audits() {
     echo ""
     echo "=== CONFIGURATION AUDIT REPORTS ==="
     kubectl get configauditreports -A -o custom-columns=\
       NAMESPACE:.metadata.namespace,\
       RESOURCE:.metadata.ownerReferences[0].name,\
       CRITICAL:.report.summary.criticalCount,\
       HIGH:.report.summary.highCount,\
       MEDIUM:.report.summary.mediumCount
   }
   ```

4. Show comparison with previous tools
   ```bash
   show_comparison() {
     cat << 'EOF'

   📊 TOOL COMPARISON:

   kube-bench:
     - Checks 100+ CIS Benchmark rules
     - Point-in-time assessment
     - Limited to cluster configuration

   kubescape:
     - Multiple frameworks (NSA, MITRE, CIS, SOC2)
     - Broader posture assessment
     - Includes remediation guidance

   trivy-operator (running now):
     - Continuous scanning (automatic on workload changes)
     - Image vulnerabilities + config audits + secrets
     - Kubernetes-native (results as CRDs)
     - Includes CIS Benchmarks from kube-bench
     - More comprehensive than either point-in-time tool

   ✅ trivy-operator supersedes kube-bench for CIS checks
   ✅ trivy-operator includes many kubescape capabilities
   ✅ trivy-operator is automated and continuous
   EOF
   }
   ```

5. Show remediation examples
   ```bash
   show_next_steps() {
     cat << 'EOF'

   🔍 To investigate a finding:
     kubectl describe vulnerabilityreport -n <ns> <report-name>
     kubectl get configauditreport -n <ns> -o yaml

   🛠️ To remediate:
     Edit the resource that trivy-operator flagged
     Trivy-operator will re-scan automatically

   📚 Next: Run hands-on validation tests
     make phase5-validate
   EOF
   }
   ```

**Files Created**:
- `scripts/phase5-trivy-operator-query.sh`

---

## Task 4: Create Attack Simulation Script

**Objective**: Create `scripts/phase5-simulate-attacks.sh` - Run 4 controlled attack tests validating Phases 1-4 controls

**Acceptance Criteria**:
- All 4 tests run without modifying cluster (except test namespace)
- Clear pass/fail for each test
- Explains what attack was attempted and what prevented it
- Generates test report in `reports/phase5-simulation-results.txt`
- Takes ~5 minutes

**Detailed Steps**:

1. Setup and teardown
   ```bash
   TEST_NS="phase5-tests"

   setup_tests() {
     kubectl create namespace "$TEST_NS" --dry-run=client -o yaml | kubectl apply -f -
     echo "[INFO] Created test namespace: $TEST_NS"
   }

   cleanup_tests() {
     kubectl delete namespace "$TEST_NS" --ignore-not-found=true
   }

   trap cleanup_tests EXIT
   ```

2. Phase 1 Test: RBAC Enforcement
   ```bash
   test_phase1_rbac() {
     echo "[TEST 1] Phase 1: RBAC Enforcement"

     # Create unprivileged service account
     kubectl -n "$TEST_NS" create serviceaccount attacker

     # Attempt to access prod secrets without permission
     if kubectl --as=system:serviceaccount:${TEST_NS}:attacker \
        get secrets -n prod &>/dev/null; then
       echo "❌ FAIL: Attacker could access prod secrets"
       return 1
     else
       echo "✅ PASS: RBAC blocked unauthorized access"
       cat >> "${REPORT_FILE}" << EOF

   TEST 1: Phase 1 - RBAC Enforcement
   Command: kubectl --as=system:serviceaccount:${TEST_NS}:attacker get secrets -n prod
   Expected: Forbidden (403)
   Result: ✅ PASS - RBAC denied access

   Why this matters:
   - Even if attacker gains pod access, RBAC limits what they can do
   - Least privilege prevents lateral movement
   EOF
       return 0
     fi
   }
   ```

3. Phase 2 Test: Pod Security Policy Enforcement
   ```bash
   test_phase2_pod_security() {
     echo "[TEST 2] Phase 2: Pod Security Policy"

     cat > /tmp/privileged-pod.yaml << 'EOF'
   apiVersion: v1
   kind: Pod
   metadata:
     name: privileged-attacker
     namespace: phase5-tests
   spec:
     securityContext:
       privileged: true
     containers:
     - name: app
       image: nginx:latest
       imagePullPolicy: Always
   EOF

     # Attempt to deploy privileged pod
     if kubectl apply -f /tmp/privileged-pod.yaml 2>&1 | grep -q "disallow-privileged"; then
       echo "✅ PASS: Kyverno policy blocked privileged pod"
       cat >> "${REPORT_FILE}" << EOF

   TEST 2: Phase 2 - Pod Security Policy
   Attempted: Deploy pod with securityContext.privileged=true
   Expected: Policy rejection
   Result: ✅ PASS - Kyverno disallow-privileged policy rejected it

   Why this matters:
   - Privileged containers can escape and compromise host
   - Policy prevents this at admission time
   - Even developers can't accidentally deploy privileged pods
   EOF
       return 0
     else
       echo "❌ FAIL: Privileged pod was allowed"
       return 1
     fi
   }
   ```

4. Phase 3 Test: NetworkPolicy Enforcement
   ```bash
   test_phase3_networkpolicy() {
     echo "[TEST 3] Phase 3: NetworkPolicy"

     # Deploy pods in test namespace
     kubectl -n "$TEST_NS" run backend --image=nginx --labels=app=backend --restart=Never
     kubectl -n "$TEST_NS" run frontend --image=busybox --labels=app=frontend --restart=Never
     kubectl -n "$TEST_NS" wait --for=condition=Ready pod/frontend --timeout=30s

     # Try to reach default namespace from test namespace (should fail)
     if timeout 5 kubectl -n "$TEST_NS" exec frontend -- \
        wget -T2 -q -O- http://kubernetes.default.svc 2>/dev/null; then
       echo "❌ FAIL: Pod reached cross-namespace service"
       return 1
     else
       echo "✅ PASS: NetworkPolicy blocked cross-namespace traffic"
       cat >> "${REPORT_FILE}" << EOF

   TEST 3: Phase 3 - NetworkPolicy
   Attempted: Cross-namespace traffic from phase5-tests to default
   Expected: Connection timeout (default deny)
   Result: ✅ PASS - NetworkPolicy blocked it

   Why this matters:
   - Default deny policy prevents lateral movement
   - Compromised pod in one namespace can't reach others
   - Limits blast radius of container compromise
   EOF
       return 0
     fi
   }
   ```

5. Phase 4 Test: Secret Policy Enforcement
   ```bash
   test_phase4_secret_policy() {
     echo "[TEST 4] Phase 4: Secret Policy"

     # Attempt to create secret without proper name
     if kubectl -n "$TEST_NS" create secret generic mydata \
        --from-literal=password=secret123 2>&1 | grep -q "require-secret-names"; then
       echo "✅ PASS: Secret policy rejected plaintext name"
       cat >> "${REPORT_FILE}" << EOF

   TEST 4: Phase 4 - Secret Policy
   Attempted: Create secret 'mydata' (no '-secret' in name)
   Expected: Policy rejection
   Result: ✅ PASS - require-secret-names policy rejected it

   Why this matters:
   - Secret names should be obvious in logs/configs
   - Plaintext names hide secrets in plain sight
   - Policy enforces naming convention
   EOF
       return 0
     else
       echo "❌ FAIL: Secret policy allowed plaintext name"
       return 1
     fi
   }
   ```

6. Generate report and summary
   ```bash
   summarize_tests() {
     if [ $FAILED -eq 0 ]; then
       echo ""
       echo "✅ All 4 attack simulations passed!"
       echo "   Your Phases 1-4 controls are working correctly"
     else
       echo ""
       echo "⚠️  ${FAILED} test(s) failed"
       echo "   Review findings and re-harden as needed"
     fi
   }
   ```

**Files Created**:
- `scripts/phase5-simulate-attacks.sh`

---

## Task 5: Create Trivy-Operator Validation Guide

**Objective**: Create `docs/phase5-trivy-operator-validation.md` - Hands-on guide to test trivy-operator detection

**Acceptance Criteria**:
- Shows how to deploy insecure workload
- Documents what trivy-operator detects
- Shows how to remediate
- Includes 2-3 realistic scenarios
- Takes user ~15 minutes to run through

**Content Structure**:

### Validation Test 1: Deploy Pod with Latest Image Tag

**Scenario**: Accidentally deploy nginx with `:latest` tag (bad practice)

**Steps**:
1. Deploy insecure pod
   ```bash
   kubectl -n default run test-nginx --image=nginx:latest
   ```

2. Wait for scan (30-60 seconds)

3. Check what trivy-operator found
   ```bash
   kubectl get vulnerabilityreports -n default -o wide
   kubectl describe vulnerabilityreport -n default <report-name>
   ```

4. Expected findings:
   - "Using image tag 'latest' is not recommended"
   - Potential CVEs in nginx image
   - Medium/High severity

5. Remediation:
   ```bash
   kubectl set image deployment/test-nginx \
     test-nginx=nginx:1.27-alpine --record

   # Wait 30 seconds, check again
   kubectl get vulnerabilityreports -n default
   ```

6. Result: Report shows reduced vulnerabilities with pinned version

**Learning Points**:
- Image tags matter (latest = unknown version)
- trivy-operator tracks changes automatically
- Remediation visible in real-time

---

### Validation Test 2: Deploy Pod Without Security Context

**Scenario**: Deploy pod without `runAsNonRoot`

**Steps**:
1. Deploy insecure pod
   ```yaml
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
       # No securityContext!
   EOF
   ```

2. Wait for scan

3. Check configuration audit report
   ```bash
   kubectl get configauditreports -n default
   kubectl describe configauditreport -n default pod-root-pod
   ```

4. Expected findings:
   - "Container should run as non-root user"
   - "No securityContext defined"
   - Medium severity

5. Remediation:
   ```yaml
   kubectl apply -f - << 'EOF'
   apiVersion: v1
   kind: Pod
   metadata:
     name: root-pod
     namespace: default
   spec:
     securityContext:
       runAsNonRoot: true
       runAsUser: 65534
     containers:
     - name: app
       image: nginx:1.27-alpine
       securityContext:
         allowPrivilegeEscalation: false
         readOnlyRootFilesystem: true
   EOF
   ```

6. Result: Report shows compliance improved

**Learning Points**:
- Security context prevents privilege escalation
- trivy-operator validates CIS Benchmark controls
- Real remediation visible in findings

---

### Validation Test 3: Deploy Pod with Exposed Sensitive Environment Variable

**Scenario**: Deploy pod with PASSWORD in environment variable

**Steps**:
1. Deploy insecure pod
   ```yaml
   kubectl apply -f - << 'EOF'
   apiVersion: v1
   kind: Pod
   metadata:
     name: secret-env-pod
     namespace: phase5-tests
   spec:
     containers:
     - name: app
       image: nginx:1.27-alpine
       env:
       - name: DATABASE_PASSWORD
         value: "super-secret-123"
   EOF
   ```

2. Check what trivy-operator detects
   ```bash
   # This may be caught by configuration audit or secret detection
   kubectl get configauditreports -n phase5-tests pod-secret-env-pod -o yaml
   ```

3. Expected findings:
   - "Sensitive data in environment variables detected"
   - HIGH severity
   - Recommendation: Use Secrets with volume mounts

4. Remediation:
   ```yaml
   # Create secret
   kubectl -n phase5-tests create secret generic db-secret \
     --from-literal=password=super-secret-123

   # Update pod to use secret volume
   kubectl apply -f - << 'EOF'
   apiVersion: v1
   kind: Pod
   metadata:
     name: secret-env-pod
     namespace: phase5-tests
   spec:
     containers:
     - name: app
       image: nginx:1.27-alpine
       volumeMounts:
       - name: secrets
         mountPath: /etc/secrets
         readOnly: true
     volumes:
     - name: secrets
       secret:
         secretName: db-secret
   EOF
   ```

5. Result: Configuration audit passes

**Learning Points**:
- Environment variables appear in pod describe, logs, metrics
- Secrets should use volume mounts
- trivy-operator catches both the problem and validates the fix

---

### Validation Test 4: Deploy Pod with Unpatched Vulnerable Image

**Scenario**: Deploy a known-vulnerable version of a package

**Steps**:
1. Deploy image with known vulnerability
   ```bash
   kubectl run vulnerable --image=nginx:1.19.0
   ```

2. Wait for vulnerability scan (2-5 minutes)

3. Check findings
   ```bash
   kubectl describe vulnerabilityreport -n default pod-vulnerable
   ```

4. Expected findings:
   - CVE-2021-4034 (possibly)
   - CRITICAL/HIGH severity
   - Recommendation: Update to patched version

5. Remediation:
   ```bash
   kubectl set image pod/vulnerable \
     vulnerable=nginx:1.27-alpine
   ```

6. Result: Vulnerability report updates

**Learning Points**:
- Old images accumulate CVEs
- Pin specific versions (not latest)
- Regular image updates necessary
- trivy-operator tracks this continuously

---

## Task 6: Create Assessment & Comparison Documentation

**Objective**: Create `docs/phase5-assessment-guide.md` - Explain what each tool does and why it matters

**Content**:

### What is kube-bench?

**Purpose**: Audit cluster configuration against CIS Kubernetes Benchmark (100+ checks)

**What it checks**:
- Master node security settings (API server, scheduler, controller-manager)
- Worker node security settings (kubelet, kube-proxy)
- Kubernetes policies (RBAC, Pod Security Admission)
- General security practices

**Example output**:
```
[PASS] 1.1.1 Ensure that the --allow-privileged argument is set to false
[PASS] 1.2.2 Ensure that the --bind-address argument is set to 127.0.0.1
[FAIL] 1.4.11 Ensure that the RotateKubeletServerCertificate argument is set to true
[WARN] 2.3.1 Ensure that user namespaces are not enabled
```

**Interpretation**:
- PASS = Control passes this CIS rule
- FAIL = Configuration doesn't match CIS recommendation
- WARN = Control not applicable or warning-level finding

**How Phases 1-4 address CIS checks**:
- Phase 1 (RBAC): Addresses rules 1.10.x (RBAC enforcement)
- Phase 2 (Pod Security): Addresses rules 2.2.x (pod security policies)
- Phase 3 (Network): Addresses rules 5.x (network policies)
- Phase 4 (Secrets): Addresses rules 1.4.x (encryption, audit)

**Limitations**:
- Point-in-time check only
- Doesn't find image vulnerabilities
- Doesn't check for secret exposure
- Manual re-run needed to detect changes

---

### What is kubescape?

**Purpose**: Comprehensive posture assessment across multiple security frameworks

**Supported Frameworks**:
- CIS Benchmarks (like kube-bench)
- NSA-CISA Hardening Guidance
- MITRE ATT&CK Framework
- SOC 2 Compliance
- Pod Security Standards

**Example output**:
```
Control: Restrict access to the admin account (NSA)
  Status: FAIL (0% compliance)
  Severity: CRITICAL
  Remediation: Ensure RBAC is properly configured

Control: Privileged containers should not be used (CIS)
  Status: PASS (100% compliance)
  Frameworks: CIS, NSA, Pod Security Standards
```

**Key differences from kube-bench**:
- Broader: Multiple frameworks vs. single CIS checklist
- Contextual: Shows why controls matter (threat models, MITRE tactics)
- Remediation-focused: Provides fix guidance
- Compliance-aware: Shows how controls address multiple standards

**Advantages**:
- Understand security from multiple angles
- See compliance across frameworks
- Better remediation guidance
- Posture score helps prioritize fixes

**Limitations**:
- May not be as deep as kube-bench on CIS checks
- Still point-in-time assessment
- Doesn't include continuous scanning
- Doesn't detect image vulnerabilities

---

### What is trivy-operator?

**Purpose**: Continuous Kubernetes-native security scanning

**What it scans**:
- **Container image vulnerabilities**: CVEs in application dependencies
- **Configuration audits**: CIS Benchmarks, security best practices
- **Secret detection**: Secrets exposed in environment variables, files
- **RBAC assessment**: Access control misconfiguration
- **Infrastructure scanning**: etcd, API server, scheduler security
- **SBOM generation**: Software Bill of Materials for compliance

**Example output** (as Kubernetes CRDs):
```bash
$ kubectl get vulnerabilityreports -n default
NAME                    REPOSITORY     TAG        CRITICAL  HIGH
deployment-nginx-xxx    nginx          latest     2         5

$ kubectl get configauditreports -n default
NAME                    CRITICAL  HIGH  MEDIUM
deployment-nginx        1         3     2

$ kubectl get secretreports -n default
NAME                    EXPOSED_SECRETS
pod-database            1
```

**How it differs from kube-bench/kubescape**:

| Aspect | kube-bench | kubescape | trivy-operator |
|--------|-----------|-----------|----------------|
| **Scope** | CIS config checks | Multi-framework posture | Image vulns + config + secrets |
| **Timing** | Point-in-time | Point-in-time | Continuous, automated |
| **Trigger** | Manual run | Manual run | Automatic on workload changes |
| **Image scanning** | No | No | Yes (full vulnerability database) |
| **Secret detection** | No | No | Yes |
| **Kubernetes-native** | No (CLI tool) | No (CLI tool) | Yes (CRDs) |
| **Best for** | CIS compliance audits | Multi-framework assessment | Ongoing security monitoring |

**Why trivy-operator supersedes the others**:
- Continuous = catches issues immediately
- Comprehensive = image vulns + config + secrets
- Native = results available in Kubernetes natively
- Automated = no manual re-runs needed
- Includes CIS checks from kube-bench
- Better for production monitoring

---

## Task 7: Create Control Mapping Documentation

**Objective**: Create `docs/phase5-control-mapping.md` - Matrix showing how Phases 1-4 controls appear in assessments

**Content**:

### Finding to Phase Control Mapping

| Finding | Tool | Phase | Control | Status | Makefile Target |
|---------|------|-------|---------|--------|-----------------|
| Privileged containers allowed | kube-bench, kubescape, trivy-operator | 2 | disallow-privileged policy | ✅ Implemented | `make phase2-harden` |
| No RBAC restrictions | kube-bench, kubescape | 1 | Role-based access control | ✅ Implemented | `make phase1-harden` |
| Secrets not encrypted at rest | kube-bench | 4 | etcd encryption | ✅ Implemented | `make phase4-up` |
| Latest image tag used | trivy-operator | 2 | require-image-tag policy | ❌ Not in Phase 2 | Enhance Phase 2 |
| Running as root | kubescape, trivy-operator | 2 | runAsNonRoot requirement | ✅ Via PSA | `make phase2-harden` |
| CVEs in image | trivy-operator only | 4 | Regular image scanning | ✅ Phase 4 does Trivy | `make phase4-scan` |

### How Each Phase Addresses Common Findings

**Phase 1: RBAC & Audit**
```
Finding: "API access not controlled"
Tool: kube-bench (rules 1.10.x), kubescape, trivy-operator (RBAC report)
Control: RoleBinding limiting service account permissions
Evidence: kubectl auth can-i shows deny
```

**Phase 2: Pod Security**
```
Finding: "Privileged containers allowed"
Tool: kube-bench (rule 2.2.1), kubescape, trivy-operator (config audit)
Control: Kyverno disallow-privileged policy + PSA restricted mode
Evidence: kubectl apply privileged pod → rejected
```

**Phase 3: Network Policies**
```
Finding: "Cross-namespace traffic allowed"
Tool: kubescape (network rules), trivy-operator (network policy check)
Control: NetworkPolicy default deny + explicit allows
Evidence: kubectl get netpol shows rules, connectivity test fails
```

**Phase 4: Secrets & Encryption**
```
Finding: "Secrets not encrypted at rest"
Tool: kube-bench (rule 1.4.10)
Control: etcd encryption via --encryption-provider-config
Evidence: Secret created, verify in etcd

Finding: "Secrets in environment variables"
Tool: trivy-operator (secret detection), Kyverno policy
Control: disallow-env-secrets policy
Evidence: kubectl apply pod with PASSWORD env → rejected
```

---

## Task 8: Update Makefile for Phase 5

**Objective**: Add Phase 5 targets to Makefile following existing patterns

**New Targets**:

```makefile
# Phase 5: Assessment & Attack Simulation
phase5: phase5-assess phase5-simulate

phase5-assess:
	$(call say,"Running point-in-time security assessment (kube-bench + kubescape)")
	@bash scripts/phase5-assess.sh

phase5-trivy-operator-install:
	$(call say,"Installing trivy-operator for continuous scanning")
	@bash scripts/phase5-trivy-operator-install.sh

phase5-trivy-operator-query:
	$(call say,"Querying trivy-operator findings")
	@bash scripts/phase5-trivy-operator-query.sh

phase5-simulate:
	$(call say,"Running attack simulation tests")
	@bash scripts/phase5-simulate-attacks.sh

phase5-validate:
	$(call say,"Running hands-on trivy-operator validation tests")
	@echo "See: docs/phase5-trivy-operator-validation.md"
	@echo "Run the validation scenarios to test trivy-operator"

phase5-reset:
	$(call say,"Cleaning up Phase 5 resources")
	@kubectl delete namespace phase5-tests --ignore-not-found=true
	@kubectl delete namespace trivy-system --ignore-not-found=true
	@rm -rf reports/phase5-*
```

**Update help text**:
```makefile
@echo "  phase5                  - Full assessment + simulation (⚠️  REQUIRES: Phase 4 cluster)"
@echo "  phase5-assess           - Run kube-bench + kubescape assessment"
@echo "  phase5-trivy-operator-install - Deploy continuous monitoring"
@echo "  phase5-trivy-operator-query   - Show findings from trivy-operator"
@echo "  phase5-simulate         - Run attack simulation tests"
@echo "  phase5-validate         - Hands-on trivy-operator validation (see docs)"
@echo "  phase5-reset            - Clean up Phase 5 resources"
```

**Files Modified**:
- `Makefile` - Add Phase 5 section

---

## Task 9: Add kubescape to devbox.json

**Objective**: Add kubescape package to devbox.json

**Changes**:
```json
{
  "packages": [
    "nixpkgs#kubectl",
    "nixpkgs#k3d",
    "nixpkgs#kubernetes-helm",
    "nixpkgs#kustomize",
    "nixpkgs#k9s",
    "nixpkgs#kubectx",
    "nixpkgs#stern",
    "nixpkgs#yq-go",
    "nixpkgs#jq",
    "nixpkgs#trivy",
    "nixpkgs#kubescape"  // ADD THIS
  ],
  "shell": {
    "init_hook": [
      "export KUBECONFIG=$PWD/.kube/config"
    ]
  }
}
```

**Files Modified**:
- `devbox.json`

---

## Task 10: Create Phase 5 Quick Reference

**Objective**: Create `docs/phase5-cheatsheet.md` - Quick reference card

**Content**:

```bash
# Full Phase 5 workflow (30 minutes)
make phase4                              # Cluster with Phase 1-4
make phase5-assess                       # Assessment: 8 min
make phase5-trivy-operator-install       # Install operator: 5 min
make phase5-trivy-operator-query         # View findings: 2 min
make phase5-simulate                     # Attack tests: 5 min

# Individual commands
make phase5-assess
  → Runs kube-bench (CIS) + kubescape (multi-framework)
  → Reports in reports/phase5-assessment/

make phase5-trivy-operator-install
  → Deploys via Helm chart to trivy-system namespace
  → Starts continuous scanning

kubectl get vulnerabilityreports -A
  → View image vulnerability findings

kubectl get configauditreports -A
  → View CIS/security configuration findings

kubectl describe vulnerabilityreport -n <ns> <name>
  → Deep dive into specific finding

# Hands-on validation (docs/phase5-trivy-operator-validation.md)
make phase5-validate                     # Run test scenarios
  → Deploy insecure pod
  → Watch trivy-operator detect it
  → Remediate and verify fix
```

**Files Created**:
- `docs/phase5-cheatsheet.md`

---

## Task 11: Testing & Validation

**Objective**: Verify all Phase 5 components work correctly

**Test Checklist**:

- [ ] Create Phase 4 cluster: `make phase4`
- [ ] Run assessment: `make phase5-assess`
  - [ ] kube-bench completes without errors
  - [ ] kubescape completes without errors
  - [ ] Reports generated in reports/phase5-assessment/
- [ ] Install trivy-operator: `make phase5-trivy-operator-install`
  - [ ] Operator pod ready in trivy-system namespace
  - [ ] No errors in helm install
- [ ] Query findings: `make phase5-trivy-operator-query`
  - [ ] Shows vulnerabilityreports
  - [ ] Shows configauditreports
  - [ ] Displays comparison with kube-bench/kubescape
- [ ] Run simulations: `make phase5-simulate`
  - [ ] All 4 tests pass
  - [ ] Report generated with explanations
- [ ] Run validation: Manual test of validation guide
  - [ ] Deploy insecure pod
  - [ ] trivy-operator detects it within 60 seconds
  - [ ] Remediate and verify detection clears
- [ ] Verify documentation
  - [ ] Assessment guide is clear and complete
  - [ ] Validation guide is step-by-step
  - [ ] Control mapping shows connections

---

## Task 12: Update Main README

**Objective**: Document Phase 5 in project README

**New README Section**:

```markdown
## Phase 5: Assessment & Attack Simulation

Validate that Phases 1-4 security controls actually work through security assessment tools and attack simulation.

**What you'll do**:
1. Run point-in-time assessment (kube-bench + kubescape)
2. Deploy continuous monitoring (trivy-operator)
3. Compare findings across tools
4. Run attack simulations validating controls
5. Hands-on validation: Deploy insecure workloads, watch trivy-operator detect them

**What you'll learn**:
- CIS Kubernetes Benchmark compliance requirements
- Multi-framework security assessment (NSA, MITRE, CIS, SOC2)
- Kubernetes-native continuous monitoring
- How each security control prevents specific attacks
- Operational security monitoring in production

**Quick start**:
```bash
make phase4
make phase5-assess
make phase5-trivy-operator-install
make phase5-trivy-operator-query
make phase5-simulate
make phase5-validate
```

**Time estimate**: 45 minutes

**Documentation**:
- `docs/phase5-assessment-guide.md` - What each tool does
- `docs/phase5-control-mapping.md` - How Phases 1-4 address findings
- `docs/phase5-trivy-operator-validation.md` - Hands-on testing guide
- `docs/phase5-cheatsheet.md` - Quick reference
```

**Files Modified**:
- `README.md`

---

## Implementation Sequence

**Suggested order** (some tasks can parallelize):

1. **Task 0** - Update devbox.json (5 min) - Required before anything else
2. **Task 1** - Assessment script (2 hours) - Core orchestrator
3. **Task 2** - Trivy-operator install script (1 hour)
4. **Task 3** - Query script (45 min) - Parallel with Task 2
5. **Task 4** - Simulation script (1.5 hours)
6. **Task 8** - Makefile updates (30 min)
7. **Task 5** - Validation guide (1 hour) - Parallel with Tasks 1-4
8. **Task 6** - Assessment guide (1.5 hours) - Parallel with Tasks 1-4
9. **Task 7** - Control mapping (1 hour) - Parallel with Tasks 1-4
10. **Task 10** - Cheatsheet (30 min)
11. **Task 9** - Update README (45 min)
12. **Task 11** - Testing & validation (2 hours)

**Total estimate**: 12-16 hours

---

## Success Criteria

Phase 5 is complete and successful when:

✅ `make phase5-assess` runs without errors, generates assessment reports
✅ `make phase5-trivy-operator-install` deploys operator successfully
✅ `make phase5-trivy-operator-query` shows findings and comparison
✅ `make phase5-simulate` runs all 4 attack tests, all pass
✅ All attack simulations have clear explanations of what prevented them
✅ Three comprehensive guides explain tools, findings, and controls
✅ Control mapping shows clear connections between findings and Phase 1-4 controls
✅ Hands-on validation guide shows how to test trivy-operator detection
✅ Cluster remains stable and unchanged after Phase 5
✅ User can understand why each Phase 1-4 control matters based on assessments
✅ User understands how to continue using trivy-operator post-lab for monitoring

---

## Post-Implementation: Production Usage

After completing Phase 5, users will have:

1. **Point-in-time assessment** - Know baseline security posture (kube-bench, kubescape)
2. **Continuous monitoring** - trivy-operator running continuously
3. **Understanding** - Know why each control exists and what it prevents
4. **Validation** - Confirmed controls actually stop attacks
5. **Foundation** - Ready to deploy to production with monitoring

Next steps for production:
- Integrate trivy-operator results into monitoring/alerting
- Set up automated remediation for fixable findings
- Implement compliance reporting (CIS, NSA-CISA)
- Establish SLA for fixing CRITICAL/HIGH findings
- Regular image scanning and patching
