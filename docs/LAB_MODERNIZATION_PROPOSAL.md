# Kubernetes Security Lab: Review & Modernization Proposal

*Status: proposal for review · Prepared 2026-10-11 · Branch `claude/lab-modernization-proposal`*

This document has four parts:
1. An audit of the lab as it stands.
2. What has changed in Kubernetes security since the lab was written. The full sourced brief is in [`docs/research/threat-landscape-2026-10.md`](research/threat-landscape-2026-10.md).
3. Where Jupyter notebooks help, and where they don't.
4. A proposed module structure and roadmap.

Only four small, mechanical fixes are implemented on this branch (see §1.4). Everything else is a proposal, so you can decide what to adopt.

---

## Summary

- **The lab's self-checks give false greens.** All four Phase 5 "attack simulations" pass even when the control they test is missing. kube-bench runs without the host access it needs. Fix this first, because every later module depends on trustworthy verification.
- **It is a hardening lab with assertions, not yet an attack lab.** There is no detection, no runtime monitoring, no supply-chain content, no node or identity attack surface, and no AI-workload content. The workbook PDF promises Falco, external secrets and Calico/Cilium, and none of them are built.
- **Several pieces are now out of date.** k3s v1.30 is past upstream EOL (2025-06-28). Kyverno `ClusterPolicy` is deprecated (CEL policy types went v1 in Kyverno 1.17). ingress-nginx was retired 2026-03-24. kube-hunter is deprecated. The Trivy releases v0.69.4–0.69.6 and `trivy-action` tags were compromised in March 2026 (CVE-2026-33634), and the lab installs Trivy without version pinning.
- **Jupyter fits well as the evidence and analysis layer.** Notebooks suit audit-log forensics, verifying detections and charting before/after posture, and they can be run headless in CI as the lab's self-test. Cluster setup and teardown should stay in Make and scripts.
- **Proposed shape:** ten modules, each following the same loop: **Observe → Detect → Harden → Verify**. Each module is mapped to the OWASP Kubernetes Top 10 (2025), MITRE ATT&CK (Containers) and the CIS Benchmark.
- **A purple-team capstone (M10):** an authorized agent that acts as an adversarial pen tester against the throwaway lab cluster, scoped by construction, and scored on how much of what it does the lab's own controls and detections catch. See §4.1.

---

## 1. Audit results

Severity: **P0** means results can't be trusted, **P1** means broken behaviour, **P2** means outdated or teaches the wrong lesson.

### 1.1 P0: validation that passes when controls are broken

| # | Where | Problem | Proposed fix |
|---|---|---|---|
| 1 | `phase5-simulate-attacks.sh` Test 4 | The pass condition is `grep -q "require-secret-names\|secret"`. A successful `kubectl create secret` prints `secret/mydata created`, which matches, so the test always passes. | Assert on the exit code and on the policy name in the denial. Better: check the Kyverno PolicyReport or the admission response. |
| 2 | Test 2 | The manifest sets `privileged: true` in the **pod** `securityContext`. That isn't a valid field (it belongs on the container). kubectl rejects the manifest with a schema error that contains "privileged", so the test passes without Kyverno ever being consulted. Also, `make phase4` runs Phase 2 in **Audit** mode, so a correct manifest would be admitted anyway. | Use a container-level manifest, and run the test against a namespace whose enforcement mode is known. Assert that the denial names the policy. |
| 3 | Test 3 | NetworkPolicies are only applied to `dev`/`prod` and are never re-applied to the Phase 4 cluster, but the test runs in `phase5-tests`. The `sleep 3` means pods usually aren't Running yet, so the exec fails and that failure counts as a pass. | Wait for readiness. Run a **positive control** (allowed traffic must succeed) before the negative check. Test in a namespace that actually has the policies. |
| 4 | Test 1 | Checks that a brand-new ServiceAccount with no bindings can't read Secrets. That is Kubernetes' default, not the Phase 1 control. | Test the Phase 1 role itself: allowed verbs succeed, adjacent verbs and resources are denied. |
| 5 | `phase5-assess.sh` kube-bench | kube-bench runs as a plain pod with no `hostPID`, no host mounts and no k3s benchmark profile, so it can't see k3s configuration or process flags. It also waits for `condition=Ready` on a pod that runs to completion. | Run it as the upstream k3s Job manifest (host mounts, `--benchmark k3s-cis-*`), wait for Job completion, and pin the image. |

The root cause is the same in every case: scripts compare output text instead of asserting on structured state. The notebook and `labkit` design in §3 addresses this directly.

### 1.2 P1: bugs

| # | Where | Problem | Status |
|---|---|---|---|
| 6 | `Makefile` | `POLICY_DIR ?= … # comment` keeps the trailing spaces (confirmed with `make -p`), so `test -d` fails in `phase2-apply`, `phase2-diff`, `phase3-apply` and `phase3-diff`. | **Fixed on this branch** |
| 7 | `Makefile` `cluster-down` | Deletes only `phase4`, but Phases 1–3 create `dev`. Following the README (`make cluster-down && make phase4`) leaves `dev` holding port 6445, so Phase 4 fails. | **Fixed on this branch** (deletes both) |
| 8 | `network-policies/40-allow-egress-external.yaml` | A copy of policy 30 with the **same name**, so applying it overwrites 30 (port 80 → 8080) and allows no external egress at all. | **Fixed on this branch.** It now allows HTTPS egress for the backend only, with private and link-local ranges excluded. |
| 9 | `Makefile` `phase3-test` | Probes the backend on port 8080, but nginx listens on 80. | **Fixed on this branch** |
| 10 | `harden-phase2.sh` / `reset-phase2.sh` | The harden script rewrites the committed policy YAMLs from heredocs, which clobbers the committed `require-labels` namespace exclusions. The reset script deletes the committed files from the working tree. | Proposed: policies live only in `policies/`. Scripts apply them and never generate or delete them. |
| 11 | `disallow-root-user.yaml` | The second `anyPattern` uses `=()` anchors throughout, so a pod with **no** securityContext matches it and root containers pass. | Proposed: replace with PSA `restricted` plus a CEL rule. |
| 12 | `disallow-privileged`, `restrict-image-registry` | Only check `containers`, not `initContainers` or `ephemeralContainers`. The registry rule rejects short names like `nginx`, which the lab's own demos use. | Proposed |
| 13 | `drop-net-raw-capability.yaml` | Sets `validationFailureAction` on a mutate-only policy, which has no effect. Lowercase `audit` and `validationFailureAction` itself are deprecated. | Proposed |
| 14 | `require-secret-names.yaml` | Enforced on **every** Secret cluster-wide, including `kube-system`, Helm release Secrets (`sh.helm.release.v1.*`) and token Secrets. Naming is not a security control. | Proposed: remove, or scope it to app namespaces as an "inventory" example |
| 15 | `harden-phase1.sh` vs `harden-phase2.sh` | Phase 1 labels `dev` as PSA `restricted`, then Phase 2 downgrades it to `baseline`. | Proposed: one deliberate PSA progression |
| 16 | `harden-phase1.sh`, `reset-phase1.sh`, docs | The server container name `k3d-dev-server-0` is hard-coded, which is wrong on the Phase 4 cluster. | Proposed: derive it from the current context |

### 1.3 P2: teaches the wrong lesson, or out of date

| # | Item | Why it matters | Proposed change |
|---|---|---|---|
| 17 | `audit-policy.yaml` logs Secrets at `RequestResponse` | Secret values end up in plaintext (base64) in `audit.log`, which undoes the Phase 4 encryption at rest. | Default to `Metadata` for secrets, tokenreviews and SA tokens. Turn the current behaviour into a deliberate exercise: "find the secret in the audit log, then fix the policy". |
| 18 | `disallow-env-secrets.yaml` | Blocks env var *names* like `DB_PASSWORD` even when the value comes from `secretKeyRef`, which is the recommended pattern. The real risk is literal values. | Flag literal `value:` on secret-like names and allow `valueFrom.secretKeyRef`. Teach volume mounts and External Secrets as the better pattern. |
| 19 | k3s `v1.30.4-k3s1` | Upstream EOL 2025-06-28. Misses user namespaces (GA 1.36), fine-grained kubelet authz (GA 1.36), MutatingAdmissionPolicy (GA 1.36), structured authn (GA 1.34) and endpoint-scoped anonymous auth (GA 1.34). | Pin the latest **v1.36.x** k3s patch, at least 1.36.5 for the CVE-2026-2270 fix. Bump on a schedule. |
| 20 | Unpinned and `:latest` images and charts | `kube-bench:latest`, `nginx:latest`, `alpine:latest`, and an unpinned Kyverno chart. Kyverno ~1.20 is expected to remove `ClusterPolicy`, which would silently break the lab. | Pin by version and digest, and keep a `versions.env` that the Makefile and scripts read. |
| 21 | Trivy supply chain (CVE-2026-33634) | Trivy v0.69.4 and Docker Hub images v0.69.5–0.69.6 were malicious. The lab gets Trivy from nixpkgs and trivy-operator from Helm without pins. | Pin the Trivy and trivy-operator versions, check them against the advisory, and use this as the opening case study for the supply-chain module. |
| 22 | Kyverno `ClusterPolicy` | Deprecated. The CEL types (`ValidatingPolicy`, `ImageValidatingPolicy`, …) are v1 since Kyverno 1.17. | Teach in-tree ValidatingAdmissionPolicy first, then Kyverno CEL. Keep one ClusterPolicy only as a "legacy" example. |
| 23 | Workbook PDF | Says it was "Created by ChatGPT", references microk8s and kube-hunter (deprecated), and promises unbuilt modules. | Replace it with the generated module index (§4). |
| 24 | README | macOS-only prerequisites, and the doc sprawl (`PHASE5_IMPLEMENTATION_PLAN.md`, 1,280 lines, at the repo root). | Linux and macOS prerequisites. Move design docs to `docs/design/`. |

### 1.4 What this branch changes

- `Makefile`: removed the trailing spaces from the directory variables, made `cluster-down` delete both lab clusters, and corrected the `phase3-test` port.
- `network-policies/40-allow-egress-external.yaml`: now a real, uniquely named HTTPS egress allow.
- Added `docs/research/threat-landscape-2026-10.md`, the sourced research brief, with UNVERIFIED flags kept.
- Added this proposal.

These were checked with `make -n` and a YAML parse. **None of them has been run against a live cluster**, because Docker wasn't available in the environment where they were written. Run `make phase1 phase2 phase3 && make cluster-down && make phase4` once to confirm.

---

## 2. What has changed since the lab was written

The full detail, with CVE IDs, versions and source links, is in the [research brief](research/threat-landscape-2026-10.md). The parts that shape this proposal:

| Area | Change | Lab implication |
|---|---|---|
| Kubernetes releases | 1.33–1.37 made several core primitives GA: user namespaces (`hostUsers: false`), fine-grained kubelet authorization, MutatingAdmissionPolicy, structured authn/authz, endpoint-scoped anonymous auth, node-bound SA tokens, SupplementalGroupsPolicy, image volumes, Pod Certificates. `gitRepo` volumes are permanently disabled. | Module content is current. Older "best practices" (annotations for AppArmor, PSP) should go. |
| RBAC | `nodes/proxy` **get** permission is effectively command execution in pods through the kubelet, and the action isn't recorded in the API audit log. Upstream response: fine-grained kubelet authz (GA 1.36), not a CVE. Many monitoring charts request this permission. CVE-2026-2270 (StatefulSet controller confused deputy) crosses namespace boundaries. | "Read-only" roles need auditing too. This is a strong RBAC-review and detection exercise. |
| Ingress | ingress-nginx retired 2026-03-24 after IngressNightmare (CVE-2025-1974) and the 2026 annotation-injection CVEs. Kubernetes Dashboard archived 2026-01-21. | Teach Gateway API. Use the retired controller as a "legacy, unpatchable component" case study. k3s ships Traefik by default. |
| Runtime / kernel | runc breakout trio (Nov 2025), containerd CRI criticals (2026), kernel "Copy Fail" CVE-2026-31431 (in CISA KEV). | Patch-management and defense-in-depth module: version inventory, user namespaces, seccomp, runtime detection. |
| Supply chain | tj-actions (CVE-2025-30066), Shai-Hulud 1 and 2 npm worms, and the Trivy/TeamPCP compromise. The latter's payload included a destructive privileged DaemonSet. cosign v3 defaults to the Sigstore bundle format. SLSA 1.2. | Signing and verification at admission, SHA-pinning, provenance. Detect unexpected DaemonSets in `kube-system`. |
| Policy engines | Kyverno is a CNCF graduate (2026-03). CEL policy types are v1, and ClusterPolicy is deprecated. Gatekeeper generates ValidatingAdmissionPolicies. | Teach in-tree VAP/MAP first, then Kyverno CEL. Unit-test policies with `kyverno test`. |
| Runtime detection | Falco 0.45 (modern eBPF, no kernel module), Tetragon 1.7 (detect and enforce), KubeArmor 1.7. | Falco + falcosidekick as the baseline. Tetragon for a blocking/enforcement exercise. |
| AI workloads | ShadowRay 2.0 (unauthenticated Ray), pickle-deserialization CVEs in model servers, NVIDIA Container Toolkit escapes, command-injection CVEs in Kubernetes MCP servers, OWASP Top 10 for Agentic Applications (Dec 2025), the upstream Agent Sandbox project. | A new module on securing AI workloads and agents in-cluster (CPU-only on k3d). |
| Frameworks | OWASP Kubernetes Top 10 **2025** (K01–K10, adds Cluster-to-Cloud Lateral Movement). MITRE ATT&CK v19 split Defense Evasion into Stealth / Defense Impairment. CIS Kubernetes Benchmark v2.0.1. NSA/CISA guide is still v1.2 (2022). | Re-map every module. Note that older detection tags may be stale. |
| Tooling | kube-hunter deprecated. rbac-police archived. KubeHound (attack-path graph, ships notebook support) and Kubernetes Goat are active. | Replace kube-hunter in the workbook. Consider KubeHound for the RBAC/attack-path module. |

---

## 3. Where Jupyter notebooks fit

**Principle:** Make and scripts stay the *engine* (cluster lifecycle, installs, resets). Notebooks become the *worksheet*: explanation, the step, the evidence and an assertion, in one place. That also removes most of today's `echo >> report` code (about half of `phase5-simulate-attacks.sh`).

There's good precedent: notebook-driven threat hunting is well established (Microsoft MSTICpy, the OTRF Threat Hunter Playbook), and KubeHound ships Jupyter support for attack-path queries.

### Good fits

| Use | Why a notebook beats today's approach | Example |
|---|---|---|
| **Audit-log forensics** | `audit.log` is JSON Lines, and pandas can filter, group and draw a timeline of it in a few cells. Today it's `grep` over `docker logs`. | "Which identities read Secrets in the last 10 minutes?" "Reconstruct the timeline of the exercise you just ran." "What did the audit log *not* see?" |
| **Detection verification** | One cell performs the test action, the next pulls Falco/Tetragon events and audit entries, the next `assert`s that an alert fired. This replaces the false-green scripts. | Runtime detection module |
| **Posture analytics** | Load kubescape, trivy-operator and PolicyReport JSON into DataFrames and chart the before/after per module. | Assessment and capstone |
| **RBAC graph analysis** | `networkx` over Roles and Bindings to surface escalation paths ("can create pods in ns X" ⇒ "can use any SA in ns X"). | Identity and RBAC module |
| **Self-testing / autograding** | `pytest --nbmake` or `papermill` runs every notebook headless against a fresh k3d cluster in CI. The lab then tests itself. | `make verify` plus a GitHub Actions workflow |

### Poor fits, which stay as they are

- Cluster create/destroy and long Helm installs. Notebooks call `make`.
- Interactive TTY work (`kubectl exec -it`, k9s). That stays in the terminal.
- Anything that must run unattended. Notebooks and scripts share the same helper module.

### Mechanics

- **Runtime:** JupyterLab 4.x via `uv` (`uv run --with jupyterlab jupyter lab`), or add `python312` and `uv` to `devbox.json`. VS Code notebooks work against the same kernel.
- **Kernel:** Python, with `%%bash` / `!` cells for kubectl one-liners. `bash_kernel` is an option for command-heavy notebooks, but one kernel keeps evidence and assertions in the same language.
- **`labkit/` helper package** (small and importable):
  - `kubectl_json()`
  - `audit_log()` → DataFrame, read from the server node
  - `falco_events()`
  - `policy_reports()`
  - `expect_denied()` / `expect_allowed()` / `expect_alert()`, with readiness waits and timeouts instead of `sleep`
  - `positive_control()`, so a negative test can never pass because the test harness itself failed
- **Git hygiene:** pair every `.ipynb` with a `jupytext` percent-format `.py` file so reviews see readable diffs. Add `nbstripout` as a pre-commit hook so outputs, and any secrets in them, are never committed.
- **Notebook template:** Objective → Setup (`make …`) → Observe → Detect → Harden → Verify (assertions) → Reflect (OWASP K8s / ATT&CK / CIS mapping).

---

## 4. Proposed module structure

Every module follows the same loop, and every "Verify" step is an assertion that fails loudly:

```
Observe the weakness  →  Detect it (audit log / runtime alert / scanner)  →  Harden  →  Verify (positive + negative controls)
```

Exercises use deliberately misconfigured workloads in the local k3d cluster only. They focus on recognising, detecting and fixing a weakness, not on building exploit tooling.

| # | Module | Builds on | New content | OWASP K8s 2025 |
|---|---|---|---|---|
| M0 | **Foundations & toolchain** | — | Pinned versions (`versions.env`), k3s v1.36.x, `labkit`, notebooks, `make verify` in CI | — |
| M1 | **Identity, RBAC & audit** | Phase 1 | RBAC review of "read-only" roles (`nodes/proxy`, `pods/exec`, `serviceaccounts/token`, impersonation, escalate/bind). SA token hygiene (`automountServiceAccountToken: false`, short-lived bound tokens). Audit-policy design. Audit-log hunting notebook. Optional KubeHound attack-path graph. | K02, K09, K10 |
| M2 | **Workload isolation & admission** | Phase 2 | PSA `restricted` as the base. In-tree ValidatingAdmissionPolicy (CEL), then Kyverno CEL `ValidatingPolicy`. Policy unit tests with `kyverno test`. seccomp `RuntimeDefault`, AppArmor fields, user namespaces (`hostUsers: false`), SupplementalGroupsPolicy `Strict`. | K01, K04 |
| M3 | **Network segmentation** | Phase 3 | Fixed policies with positive and negative controls. Protecting admission webhooks and controller ports. Egress control, including link-local metadata addresses. Optional Cilium for L7 and FQDN policy, plus Hubble flow evidence. | K05, K08 |
| M4 | **Secrets & data protection** | Phase 4 | Audit-log secret-leak exercise (finding #17). Encryption-at-rest verification by reading etcd/kine directly. Key rotation. External Secrets Operator with a local OpenBao/Vault dev server. Secret-scanning in manifests and images. | K03 |
| M5 | **Software supply chain** *(new)* | — | Case studies: Trivy/TeamPCP, tj-actions, Shai-Hulud. Local k3d registry. cosign v3 signing and attestations, SBOM (syft/Trivy), VEX. Admission verification with Kyverno `ImageValidatingPolicy` or sigstore policy-controller. SHA-pinned CI. Detecting unexpected DaemonSets. | K01, K04, K07 |
| M6 | **Runtime detection & response** *(new)* | — | Falco (modern eBPF) + falcosidekick → file/webhook → notebook. Detection-verification notebook for shell-in-container, sensitive file reads, unexpected outbound connections and token reads. Optional Tetragon enforcement. Incident timeline reconstruction combining audit log and Falco events. | K10 |
| M7 | **Nodes, runtime & cluster components** *(new)* | Phase 5 kube-bench | Correct k3s CIS run. kubelet hardening (anonymous auth, authz mode, fine-grained kubelet authz). Runtime/kernel version inventory against advisories (runc, containerd, kernel). Ingress: Gateway API migration, with ingress-nginx retirement and IngressNightmare as a case study on exposed admission webhooks. | K06, K07 |
| M8 | **AI workloads & agents on Kubernetes** *(new)* | — | CPU-only on k3d. Exposed model-serving / Ray control-plane case study and hardening (auth, NetworkPolicy, no public Services). Model artifact safety (safetensors vs pickle, scanning with picklescan/ModelScan). An in-cluster agent / MCP server with a least-privilege SA, egress allow-lists and an approval boundary, mapped to the OWASP Agentic Top 10. Agent Sandbox / gVisor as an isolation option. GPU-toolkit CVEs as architecture discussion only. | K01, K02, K06 |
| M9 | **Assessment & capstone** | Phase 5 | Rebuilt Phase 5: kubescape + trivy-operator + kube-bench results loaded into notebooks, with a before/after scorecard per module. Capstone: a pre-built "insecure-shop" namespace containing ~10 planted weaknesses, which learners find, detect and fix, graded by a notebook. | All |
| M10 | **Agent-driven adversarial testing (purple team)** *(new)* | M1–M9, esp. M6 | An authorized AI agent that probes the local lab cluster against a defined scope, maps findings to ATT&CK, and — the point of the module — scores how many of its actions the M6 detections and admission controls caught. See §4.1. | K10, plus whichever the run touches |

### 4.1 M10 in detail: the adversarial-testing agent

The ask is to be able to point an agent at the lab and have it act as an adversarial pen tester. The way to make that a *lab exercise* rather than just a scan is to run it as **purple team**: the agent attacks, the lab records, and the deliverable is a scorecard of **what was blocked and what was detected**, not just what the agent managed to do. That turns every run into a direct test of M1–M9.

**Operating rules (built into the harness, not left to the prompt):**

- **Scope by construction.** The agent is handed a kubeconfig for a freshly built, throwaway k3d lab cluster and nothing else. The target list is a file (namespaces, Services, node IPs) generated from that cluster. The harness refuses to start if the current context isn't a `k3d-*` lab cluster, and a `--i-understand` style guard plus a printed scope banner make "this is the lab, nothing else" explicit. This is the same authorization boundary a real engagement has — it's just enforced in code because the operator is an agent.
- **A rules-of-engagement file** (`m10/engagement.yaml`): allowed target cluster, time box, techniques that are in scope, and a hard deny-list (no egress to anything off the lab subnet, no attempt to reach the host, no destructive payloads). The agent reads it as its brief; the harness enforces the network and target parts regardless of what the agent decides.
- **Known techniques only.** The agent works from a catalog of recognised, published techniques drawn from the lab's own modules and framework mappings (MITRE ATT&CK Containers, the Kubenomicon matrix, Stratus Red Team's Kubernetes techniques). It chains and prioritises them; it is not there to author novel exploit code. Where a step would need a real exploit binary, it uses the lab's existing, pinned tooling (kubeletctl, Stratus Red Team, Kubernetes Goat scenarios) rather than writing one.
- **Everything is logged.** Every command, request and result is written to a run transcript. Because the cluster has M1 audit logging and M6 Falco running, each agent action can be lined up against what the cluster saw.

**What the agent does per run:**

1. **Recon** from an assumed starting position you choose — the realistic one is "inside a pod with a default ServiceAccount" (the most common real-world foothold), with "unauthenticated from the pod network" as a second scenario. Enumerate reachable APIs, tokens, RBAC, Services, and node/kubelet surface.
2. **Plan** a path against the ATT&CK Containers tactics (discovery → credential access → lateral movement → privilege escalation), citing the technique IDs it intends to use.
3. **Act** within the engagement scope, recording each attempt and its outcome (blocked at admission, denied by RBAC, denied by NetworkPolicy, or succeeded).
4. **Report** into a notebook: a timeline, an ATT&CK-style coverage grid, and for each attempted technique three columns — **attempted / prevented / detected** — with the audit-log entry or Falco alert that caught it (or a gap where nothing did).

**Why this is the most valuable module for you specifically:** it closes the loop on the whole lab. M1–M9 add controls and detections; M10 is the independent check that they actually fire under pressure. A detection gap the agent finds (for example the `nodes/proxy` → exec path that produces no audit event) becomes the next thing to fix, and the next run proves the fix.

**Implementation options, simplest first:**

- **(a) Scripted scenario-runner.** The agent is given a fixed menu of lab techniques and a notebook that runs each, records prevented/detected, and scores it. Deterministic, safe, good for CI. This is the floor, and it's worth building even on its own.
- **(b) Claude Code / Agent SDK harness.** A subagent is given the engagement file, the scoped kubeconfig, and a small read-mostly toolset (kubectl, the catalogued offensive tools), and is told to pursue the objective and produce the report. More realistic and open-ended; must run against the throwaway cluster only, with the network deny-list enforced by the lab's own egress NetworkPolicies and a scope-guard wrapper on every tool call.
- **(c) Existing frameworks as the engine.** Drive **Stratus Red Team** (detonate-and-detect) and selected **Kubernetes Goat** scenarios from the same notebook, and let the agent choose and sequence them. Least custom code, strong provenance.

A sensible build order is (a) → (c) → (b): prove the scoring loop with scripted techniques, wire in the established frameworks, then let the agent drive. Keep this module last on the roadmap because its scorecard is only meaningful once M6 detection and the M1–M4 controls exist to be tested.

### Suggested repo layout

```
Makefile                  # engine: cluster lifecycle, installs, module targets, verify
versions.env              # single source of pinned versions/digests
labkit/                   # python helpers shared by notebooks + scripts
modules/
  m1-identity/            # README.md, NN-*.ipynb (+ paired .py), manifests/, policies/
  m2-workload/
  ...
policies/                 # (migrated into modules/*/policies over time)
docs/
  LAB_MODERNIZATION_PROPOSAL.md
  research/threat-landscape-2026-10.md
  design/                 # PHASE5_IMPLEMENTATION_PLAN.md etc. moved here
.github/workflows/verify.yml   # k3d + nbmake headless run
```

---

## 5. Roadmap

| Step | Scope | Outcome |
|---|---|---|
| **A. Trust the results** | Fix P0 #1–5 and P1 #10–16. Pin all versions (incl. Trivy per CVE-2026-33634). Bump k3s to v1.36.x. Audit policy to `Metadata` for secrets. | Existing Phases 1–5 run green *only* when controls actually work. |
| **B. Notebook foundation** | `labkit`, jupytext and nbstripout. First notebook: **M1 audit-log hunting**. Then convert Phase 5 into the M9 scorecard notebook. Add `make verify` and a CI workflow. | A working proof of the notebook approach on the highest-value use case. |
| **C. Detection** | M6 (Falco). Retrofit "Detect" steps into M1–M4. | The lab becomes attack/defense rather than hardening-only. |
| **D. New surfaces** | M5 supply chain, then M7 nodes/components. | Covers the 2025–2026 incident classes. |
| **E. AI workloads** | M8. | Covers the newest initial-access surface. |
| **F. Capstone & docs** | M9 capstone, replace the workbook PDF, README for Linux and macOS, move design docs. | A coherent course. |
| **G. Adversarial agent (purple team)** | M10. Start with the scripted scenario-runner and scorecard (option a), add Stratus Red Team / Kubernetes Goat (option c), then the Agent-SDK harness (option b) with the scope-guard and egress deny-list. | An authorized agent that independently tests whether the M1–M9 controls and detections actually fire, and reports the gaps. |

Step A is self-contained and worth doing even if nothing else is adopted. Step G depends on C (detection) being in place, because its scorecard measures what the detections catch.

---

## 6. Open decisions for you

1. **CNI:** stay on k3s's built-in flannel + network-policy controller (simplest), or switch to Cilium? Cilium gives L7/FQDN policy, Hubble evidence and a path to Tetragon, but makes the cluster heavier.
2. **Runtime detector:** Falco only, or Falco plus a Tetragon enforcement exercise?
3. **Phase names vs modules:** keep "Phase 1–5" naming for continuity, or move to M0–M9?
4. **Single cluster:** the Phase 4 rebuild exists only because encryption is enabled at creation. Creating one cluster with encryption and audit from the start (and keeping a "before" profile for comparison exercises) would simplify the flow.
5. **User namespaces in k3d:** `hostUsers: false` needs idmapped-mount support from the host kernel and the containerd-in-Docker setup. This needs a short spike before M2 relies on it.
6. **Scope of M8:** CPU-only toy model server and MCP server, or also optional GPU/cloud material?
7. **M10 agent autonomy:** how far up the (a)→(c)→(b) ladder do you want to go — a deterministic scripted runner, framework-driven, or a free-driving Agent-SDK harness? And which starting position is the default: assumed pod foothold, or unauthenticated from the pod network?

---

## Appendix: sources

All dates, CVE IDs, versions and source links are in [`docs/research/threat-landscape-2026-10.md`](research/threat-landscape-2026-10.md). Items that rest on secondary sources or couldn't be confirmed are marked **UNVERIFIED** there. Check them before citing them in lab material.
