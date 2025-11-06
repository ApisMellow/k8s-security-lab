
# 🧩 Kubernetes Security Lab – Phase 2: Policy Enforcement & Admission Control

**Objective:**  
Extend the Phase 1 cluster (RBAC + Audit + PSA) into a *policy-driven* environment that automatically enforces security posture using **Pod Security Admission (PSA)** and **Kyverno**.  
You’ll learn how to codify baseline restrictions, detect violations, and progressively harden namespaces.

---

## 🔖 Learning Goals

| Area | Description | Tool |
|------|--------------|------|
| Pod Security Admission | Enforce restricted pod behavior at the namespace level | Built-in |
| Admission Control | Enforce organizational policies dynamically | Kyverno |
| Policy Lifecycle | Distinguish baseline → restricted → audit-mode policies | PSA labels + Kyverno |
| Policy Violation Visibility | Detect and audit denied resources | Audit log + Kyverno reports |
| Policy Shift | Practice promoting policies from *warn* → *enforce* | Kyverno |

---

## ⚙️ Prerequisites

- Phase 1 environment and Makefile complete  
- `k3d` cluster with API bound to `127.0.0.1`  
- `kubectl`, `helm`, `kustomize`, and `jq` installed  
- Devbox shell working with `KUBECONFIG=$PWD/.kube/config`

---

## 🧭 Lab Roadmap

### **1. Verify Pod Security Admission (PSA) Framework**

1. Confirm PSA is active:
   ```bash
   kubectl get --raw /api/v1/namespaces/default | jq '.metadata.labels'
   ```
2. Label namespaces:
   ```bash
   kubectl label ns dev pod-security.kubernetes.io/enforce=baseline --overwrite
   kubectl label ns prod pod-security.kubernetes.io/enforce=restricted --overwrite
   ```
3. Deploy intentionally non-compliant pod:
   ```bash
   kubectl -n dev run privileged-test --image=nginx --overrides='{"spec":{"containers":[{"name":"nginx","image":"nginx","securityContext":{"privileged":true}}]}}'
   ```
4. Observe rejection (`privileged` not allowed under baseline/restricted).

5. View audit entry:
   ```bash
   docker exec -i k3d-dev-server-0 grep -C3 '"reason":"Create"' /var/lib/rancher/k3s/server/logs/audit.log | grep privileged
   ```

---

### **2. Introduce Kyverno**

1. Install via Helm:
   ```bash
   helm repo add kyverno https://kyverno.github.io/kyverno/
   helm repo update
   helm install kyverno kyverno/kyverno -n kyverno --create-namespace
   ```
2. Confirm pods are running:
   ```bash
   kubectl -n kyverno get pods
   ```

3. Review admission controller logs:
   ```bash
   stern -n kyverno kyverno
   ```

---

### **3. Apply Kyverno Baseline Policies**

> 🧱 Goal: Define guardrails that mirror PSA but extend to other resources.

1. Create a `policies/` folder in the project:
   ```
   policies/
     ├── disallow-privileged.yaml
     ├── disallow-root-user.yaml
     ├── restrict-image-registry.yaml
     └── require-labels.yaml
   ```

2. Example – `disallow-privileged.yaml`:
   ```yaml
   apiVersion: kyverno.io/v1
   kind: ClusterPolicy
   metadata:
     name: disallow-privileged
   spec:
     validationFailureAction: audit
     background: true
     rules:
       - name: privileged-containers
         match:
           resources:
             kinds:
               - Pod
         validate:
           message: "Privileged containers are not allowed"
           pattern:
             spec:
               containers:
                 - =(securityContext):
                     =(privileged): false
   ```

3. Apply all policies:
   ```bash
   kubectl apply -f policies/
   ```

4. Verify:
   ```bash
   kubectl get clusterpolicies
   kubectl get policyreport -A
   ```

5. Deploy test pod again — verify violation is **recorded (audit)**, not blocked yet.

---

### **4. Promote Policies to Enforce**

1. Edit the ClusterPolicies to:
   ```yaml
   validationFailureAction: enforce
   ```
2. Re-apply and attempt to deploy the same non-compliant pod.
3. Verify the rejection message and confirm via:
   ```bash
   kubectl get events -A | grep Kyverno
   ```

---

### **5. Explore Policy Violation Reports**

- View summarized report:
  ```bash
  kubectl get policyreport -A -o wide
  ```
- Describe a specific one:
  ```bash
  kubectl -n dev describe policyreport <name>
  ```
- Watch for updates:
  ```bash
  watch kubectl get policyreport -A
  ```

---

### **6. Integrate with Audit and Metrics**

- Confirm Kyverno webhook decisions appear in the API audit log.
- Use `kubectl top pod -n kyverno` to inspect performance impact.
- Optional:  
  Install [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/) to validate policies offline:
  ```bash
  kyverno apply policies/ --resource manifests/test-pod.yaml
  ```

---

### **7. Hardening Validation Script (Phase 2)**

Plan to create a future `scripts/harden-phase2.sh` that will:
- Check PSA labels (baseline/restricted)
- Validate Kyverno CRDs are installed
- Detect at least 3 ClusterPolicies
- Create a non-compliant pod and expect rejection
- Confirm PolicyReports exist and are populated

---

### **8. Reset Script (Phase 2)**

Add `scripts/reset-phase2.sh` to:
- Delete Kyverno namespace and ClusterPolicies
- Remove PSA labels
- Clear policyreports
- Optionally re-create clean cluster for re-run demos

---

## ✅ Completion Criteria

| Checkpoint | Validation |
|-------------|-------------|
| PSA Enforced | Non-compliant pod rejected |
| Kyverno Installed | All pods in `kyverno` namespace ready |
| Baseline Policies Active | 3+ policies in `audit` mode |
| Enforced Policies Verified | Policy blocks invalid pod creation |
| PolicyReports Present | `kubectl get policyreport -A` shows entries |
| Audit Log Captures Events | DELETE/CREATE entries for denied pods |

---

## 📚 Reference Material

- [Kubernetes → Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kyverno → Policy Examples](https://kyverno.io/policies/)
- [Kyverno → Policy Lifecycle](https://kyverno.io/docs/writing-policies/validation/#validationfailureaction)
- [Kyverno CLI Docs](https://kyverno.io/docs/kyverno-cli/)
- [SUSE/Rancher – k3s Admission Webhooks](https://docs.k3s.io/advanced#api-server-flags)
