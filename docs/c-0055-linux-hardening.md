# C-0055: Linux Hardening Control

## Overview

C-0055 is a security control that verifies containerized workloads have Linux hardening mechanisms enabled. This control is part of the NSA-CISA and CIS frameworks and falls under the **Workload** security category, specifically the **Node escape** subcategory.

## What Does This Control Check?

The control verifies that at least ONE of the following Linux hardening mechanisms is configured in a workload's securityContext:

- **seccomp** (Secure Computing Mode) - Restricts syscalls available to containers
- **SELinux** (Security-Enhanced Linux) - Mandatory Access Control system
- **AppArmor** - Capabilities-based access control
- **Linux Capabilities** - Fine-grained privilege controls

A workload **fails** this check if none of these mechanisms are configured.

## Why Is Linux Hardening Important?

Without Linux hardening, a compromised container can potentially:

1. **Execute arbitrary system calls** - Access any kernel functionality without restriction
2. **Access host resources** - Break isolation boundaries
3. **Perform privilege escalation** - Gain elevated privileges inside the container
4. **Escape to the host** - Move from container to underlying host system

Linux hardening creates multiple layers of defense by restricting what system calls and operations are available to a container, significantly reducing the attack surface.

## What Are Seccomp Profiles?

### Definition

**Seccomp** (Secure Computing Mode) is a Linux kernel security feature that restricts the syscalls (system calls) available to a process. A seccomp profile is a set of rules defining which syscalls are allowed, blocked, or should trigger specific actions.

### How Seccomp Works

1. **System Call Interception**: The kernel intercepts every system call made by the container process
2. **Rule Matching**: The seccomp profile evaluates the syscall against its rules
3. **Action**: Based on the rule match, the kernel allows, denies, or logs the call:
   - `SCMP_ACT_ALLOW` - Permit the syscall to execute
   - `SCMP_ACT_ERRNO` - Block and return error (container sees syscall failed)
   - `SCMP_ACT_KILL` - Terminate the process immediately
   - `SCMP_ACT_LOG` - Log the syscall but allow it
   - `SCMP_ACT_TRACE` - Trigger debugging trace

### Seccomp in Kubernetes Context

Kubernetes supports two seccomp modes:

#### 1. **RuntimeDefault** (Recommended)
Uses the container runtime's default seccomp profile, which is maintained by the runtime vendor (Docker, containerd, etc.) and blocks known dangerous syscalls while allowing common application syscalls.

**Advantages:**
- Maintained by runtime vendor
- Automatically updated with security patches
- Works with most applications without modification
- No custom profile management needed

#### 2. **Localhost**
Uses a custom seccomp profile file stored on the node.

**Advantages:**
- Full control over allowed syscalls
- Can be tailored to specific application needs

**Disadvantages:**
- Requires managing profile files across all nodes
- Profile must be pre-staged at node-specific paths
- More operational overhead

### Example: Blocked Syscalls

A typical seccomp profile blocks dangerous syscalls such as:

- `ptrace` - Process tracing (used in privilege escalation)
- `open_by_handle_at` - File handle operations
- `kexec_load` - Kernel image loading
- `clone` with certain flags - Process creation
- `bpf` - eBPF operations
- `perf_event_open` - Performance monitoring (can leak kernel addresses)

Allowed syscalls typically include:
- `read`, `write`, `open`, `close` - File operations
- `connect`, `bind`, `listen` - Network operations
- `mmap`, `mprotect` - Memory operations
- `exit`, `exit_group` - Process termination
- `sigaction`, `sigprocmask` - Signal handling

## Current Status in Your Cluster

Running `make phase5-assess` shows:

- ✅ **9 resources PASS** - Have at least one hardening mechanism configured
- ❌ **2 resources FAIL** - Have none of these mechanisms configured
- ⏭️ **1 resource IGNORED** - Excluded from check

## Remediation: Adding Seccomp to Your Workloads

### Option 1: Use RuntimeDefault (Simplest & Recommended)

Add to your workload's `securityContext`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-secure-app
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      # Pod-level seccomp (applies to all containers)
      securityContext:
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: app
        image: myimage:latest
        ports:
        - containerPort: 8080
```

**What happens:**
- Kubernetes applies the container runtime's default seccomp profile
- The profile blocks known dangerous syscalls
- Most standard applications work without issues
- The profile is automatically maintained by your runtime vendor

### Option 2: Container-Level Seccomp

If you need fine-grained control per container:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myimage:latest
        securityContext:
          seccompProfile:
            type: RuntimeDefault

      - name: sidecar
        image: sidecar:latest
        # Different profile per container
        securityContext:
          seccompProfile:
            type: RuntimeDefault
```

### Option 3: StatefulSet Example

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-stateful-app
spec:
  serviceName: my-app
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: app
        image: myimage:latest
        volumeMounts:
        - name: data
          mountPath: /data

  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
```

## Verification

After applying the changes, verify the seccomp profile is in place:

```bash
# Check if pod has seccomp configured
kubectl get pod <pod-name> -o jsonpath='{.spec.securityContext.seccompProfile}'

# Output should show:
# {"type":"RuntimeDefault"}
```

Run Phase 5 assessment again:

```bash
make phase5-assess
```

You should see the failed resources count decrease as workloads are updated.

## Integration with Phase 4

Your Phase 2 baseline policies already include:
- Disallow privileged containers
- Prevent host path mounting
- Require non-root users
- Drop NET_RAW capability

Adding seccomp profiles **complements** these controls by:
- Restricting syscalls (prevents exploitation even if container was compromised)
- Blocking kernel-level attacks (privilege escalation attempts)
- Reducing blast radius of container escapes

## Troubleshooting

### Application Fails with Seccomp RuntimeDefault

If your application breaks with `RuntimeDefault` seccomp:

1. **Check logs** for "Operation not permitted" errors
2. **Identify the blocked syscall** from error messages
3. **Switch to localhost profile** and create custom profile allowing that syscall
4. **Test thoroughly** before rolling to production

### Creating a Custom Seccomp Profile (Advanced)

Create a custom profile file at `/var/lib/kubelet/seccomp/profiles/my-profile.json`:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ]
    }
  ],
  "syscalls": [
    {
      "names": [
        "read",
        "write",
        "open",
        "close",
        "stat",
        "fstat",
        "lstat",
        "poll",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Then reference it:

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: my-profile.json
```

## Best Practices

1. **Start with RuntimeDefault** - Most applications work without modification
2. **Test before production** - Verify your app works with seccomp
3. **Monitor for failures** - Watch logs for "Operation not permitted" errors
4. **Combine with other controls** - Use alongside capabilities dropping and read-only filesystems
5. **Keep profiles updated** - If using Localhost, update profiles with security patches

## References

- [Kubernetes Seccomp Documentation](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Seccomp Filter Syntax](https://www.man7.org/linux/man-pages/man2/seccomp.2.html)
- [OCI Image Spec - Security](https://github.com/opencontainers/image-spec/blob/main/config.md)
- [NSA Kubernetes Hardening Guidance](https://media.defense.gov/Nov%202021/pdf/NSA_CSI_Kubernetes_Hardening_Guidance.pdf)
