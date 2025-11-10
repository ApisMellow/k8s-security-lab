# Phase 1 Walkthrough: RBAC & Namespaces

This document walks through each step of Phase 1, explaining the intent and meaning of each YAML application.

## Overview

Phase 1 teaches the fundamentals of Kubernetes security through:
1. **Namespace isolation** - logical separation of resources
2. **RBAC (Role-Based Access Control)** - least-privilege access control
3. **API Audit Logging** - tracking who did what and when

---

## Step 1: Apply Namespaces (`manifests/namespaces.yaml`)

### What it does
Creates two isolated namespaces in your cluster: `dev` and `prod`.

### Why this matters
Namespaces are Kubernetes' way of creating logical divisions within a cluster. They allow you to:
- Isolate resources and teams from each other
- Apply different policies to different environments
- Prevent accidental cross-environment changes
- Enable multi-tenancy on a single cluster

### The manifest 
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dev
---
apiVersion: v1
kind: Namespace
metadata:
  name: prod
```

---

## Step 2: Apply RBAC Configuration (`manifests/rbac-dev-view.yaml`)

### What it does
Sets up **least-privilege access** for a specific service account in the `dev` namespace.

### Why this matters
By default, many systems grant broad permissions. This creates security risks—a compromised account can do too much damage. RBAC enforces the **principle of least privilege**: give identities only the minimum permissions they need.

### Breaking down the manifest

#### Part 1: ServiceAccount (`sa-dev-view`)
Creates an identity called `sa-dev-view` in the `dev` namespace. Think of this as a "user account" for applications or processes running in that namespace. It's not a real person—it's an identity that pods can assume.

#### Part 2: Role (`dev-view`)
Defines what permissions are allowed. Specifically, this role grants permission to:
- **get** pods (view details of a single pod)
- **list** pods (see all pods in the namespace)
- **watch** pods (get real-time notifications when pods change)

These are **read-only** operations. The role does NOT allow:
- Creating pods
- Deleting pods
- Modifying pods
- Accessing secrets or other resources

#### Part 3: RoleBinding (`dev-view-binding`)
Connects the ServiceAccount to the Role. It says: "The service account `sa-dev-view` is now allowed to perform the actions defined in the `dev-view` role."

### Summary
It creates a restricted identity (`sa-dev-view`) that can only **read pod information** in the `dev` namespace—nothing more. This follows the **principle of least privilege**: give users/accounts only the minimum permissions they need to do their job, nothing extra. Any process using this service account will be blocked if it tries to create, delete, or modify pods, or access secrets.

---

## Step 3: Verify RBAC with Tests (`scripts/harden-phase1.sh`)

### What it does
Runs a series of tests to verify that RBAC is working correctly and enforcing the least-privilege model.

### What gets tested
1. **kubectl reachability** - Can we talk to the cluster?
2. **API binding** - Is the API server bound to localhost?
3. **Namespace & RBAC presence** - Do all the resources exist?
4. **RBAC permission tests**:
   - ✅ List pods (should SUCCEED)
   - ✅ Watch pods (should SUCCEED)
   - ❌ Create pods (should FAIL)
   - ❌ Delete pods (should FAIL)
   - ❌ Access secrets (should FAIL)
5. **Pod Security Admission** - Are namespace labels correctly applied?
6. **Audit logging** - Is the audit file present and logging events?

### Why this matters
Testing is essential to verify that your security configuration actually works. It's not enough to write the YAML—you need to prove that:
- Allowed operations succeed
- Denied operations fail
- The system logs what's happening

---

## API Audit Logging

### What it does
Enables detailed logging of all API requests and their results, including who made the request, what they tried to do, and whether it was allowed or denied.

### Why this matters
Audit logging provides accountability and visibility:
- Detect unauthorized access attempts
- Understand who accessed what resources
- Investigate security incidents
- Comply with compliance requirements (SOC 2, HIPAA, etc.)

### How to enable
Recreate your cluster with audit logging:
```bash
./scripts/cluster-up-with-audit.sh
```

Then after running tests, check the audit log:
```bash
docker logs $(docker ps --filter name=k3d-dev-server-0 -q) 2>&1 | grep audit
```

---

## Putting it all together

The Phase 1 labs demonstrate a complete security posture:

| Layer | Control | Purpose |
|-------|---------|---------|
| **Isolation** | Namespaces | Separate dev/prod resources |
| **Authorization** | RBAC | Enforce least-privilege access |
| **Accountability** | Audit Logging | Track all API activity |

Together, these make it difficult for:
- Accidental mistakes to spread across environments
- Compromised accounts to damage sensitive resources
- Unauthorized changes to go undetected

