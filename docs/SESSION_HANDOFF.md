# Session handoff — k8s-security-lab modernization

*Written 2026-10-11 so a fresh session (or a human) can pick up with full context. This is notes, not a spec — the authoritative plan is [`LAB_MODERNIZATION_PROPOSAL.md`](LAB_MODERNIZATION_PROPOSAL.md).*

## How to resume in a new session

Paste something like this as the opening message:

> This repo (`k8s-security-lab`) has a modernization proposal on branch
> `claude/lab-modernization-proposal`. Read `docs/SESSION_HANDOFF.md`,
> `docs/LAB_MODERNIZATION_PROPOSAL.md`, and `docs/research/threat-landscape-2026-10.md`,
> then start on **Step A** (make the Phase 5 checks trustworthy + pin versions + bump k3s).
> Docker is available / not available here: <say which>.

Everything below is already committed on that branch.

## What this is

A hands-on Kubernetes security lab (local k3d cluster, Makefile-driven, 5 phases:
RBAC/audit → pod security/Kyverno → NetworkPolicy → encryption/secrets → kube-bench/kubescape/trivy-operator).
Goal of this work: review it, modernize it to current (2024–2026) guidance, work out where Jupyter
notebooks help, and add a way to point an agent at it as an authorized adversarial pen tester.

## State of the branch `claude/lab-modernization-proposal`

Commits on top of `main`:
1. **Four verified fixes** (checked with `make -n` + YAML parse only; **not run on a live cluster** — no Docker in this environment):
   - Makefile `POLICY_DIR`/`NP_DIR` had trailing spaces from inline comments → broke `phase2-apply`/`phase3-apply`. Fixed.
   - `make cluster-down` only deleted `phase4`; phases 1–3 use cluster `dev` → port 6445 stayed held → `make phase4` failed. Now deletes both.
   - `phase3-test` probed backend on 8080; nginx listens on 80. Fixed.
   - `network-policies/40-allow-egress-external.yaml` was a duplicate of policy 30 (same name, so it overwrote it). Now a real HTTPS-only egress allow excluding private + link-local ranges.
2. **`docs/research/threat-landscape-2026-10.md`** — sourced research brief (CVEs, k8s 1.30→1.37 security features, frameworks, supply chain, runtime detection, policy engines, AI workloads). UNVERIFIED items are flagged; check those before citing.
3. **`docs/LAB_MODERNIZATION_PROPOSAL.md`** — the main document: audit findings, where Jupyter fits, modules M0–M10, roadmap, open decisions.
4. **This handoff.**

No PR opened. Nothing merged to `main`.

## The audit, in one screen

**P0 — the lab's self-checks lie.** All four Phase 5 "attack simulations" pass even when the control is missing:
- Secret test passes because the success message contains the word "secret".
- Privileged-pod test puts `privileged:true` at pod level (invalid field) → kubectl schema-rejects it → counted as a pass, Kyverno never runs. Also phase2 runs in Audit mode so a valid manifest would be admitted.
- NetworkPolicy test runs in a namespace with no policies, `sleep 3` means pods aren't Ready → failed exec counted as a pass.
- RBAC test checks default-deny (new SA, no bindings), not the Phase 1 role.
- kube-bench runs as a plain pod (no hostPID/host mounts/k3s profile) → results meaningless; also `wait condition=Ready` on a run-to-completion pod.

**P1 bugs** (4 fixed above; rest proposed): harden-phase2 rewrites/clobbers committed policy files; `disallow-root-user` lets no-securityContext pods through; policies ignore init/ephemeral containers; `require-secret-names` enforced cluster-wide incl. kube-system/Helm secrets; PSA label fights between phase1 (restricted) and phase2 (baseline); hard-coded `k3d-dev-server-0`.

**P2 outdated / wrong lesson:** audit policy logs Secret *values* in plaintext (undoes encryption-at-rest — turn into a deliberate exercise); `disallow-env-secrets` blocks env *names* even via secretKeyRef (recommended pattern); k3s v1.30 is EOL; `:latest`/unpinned images incl. Kyverno chart (ClusterPolicy deprecated, ~1.20 removes it); Trivy unpinned (CVE-2026-33634 shipped malicious Trivy v0.69.4–0.69.6 + trivy-action tags in Mar 2026); workbook PDF references microk8s/kube-hunter (deprecated) and promises unbuilt modules.

## What changed in the world (why modernize)

- **ingress-nginx retired 2026-03-24** (after IngressNightmare CVE-2025-1974); Dashboard archived 2026-01-21. Teach Gateway API.
- **New GA primitives:** user namespaces `hostUsers:false` (1.36), fine-grained kubelet authz (1.36, fixes the `nodes/proxy` GET→exec issue that produces *no* audit log), MutatingAdmissionPolicy (1.36), structured authn (1.34), endpoint-scoped anonymous auth (1.34), node-bound SA tokens (1.33); gitRepo volume permanently disabled (1.36).
- **Kyverno** is CNCF-graduated; CEL policy types (`ValidatingPolicy`, `ImageValidatingPolicy`) are GA since 1.17; `ClusterPolicy` deprecated. In-tree ValidatingAdmissionPolicy is GA (1.30).
- **Runtime detection:** Falco 0.45 (modern eBPF, no kernel module) is the k3d baseline; Tetragon/KubeArmor for enforcement. kube-hunter deprecated, rbac-police archived.
- **Supply chain** incidents: Trivy/TeamPCP (directly relevant), tj-actions, Shai-Hulud npm worms; cosign v3.
- **AI workloads** are a real initial-access surface: ShadowRay, model-server pickle RCEs, Kubernetes MCP-server command-injection CVEs; OWASP Agentic Top 10 (Dec 2025); upstream Agent Sandbox.
- **Frameworks:** OWASP K8s Top 10 **2025**; CIS Benchmark v2.0.1; NSA/CISA guide still v1.2 (2022).

## Where Jupyter fits

Make/scripts stay the engine (cluster lifecycle, installs). Notebooks become the worksheet: explain → do → show evidence → assert. Good fits: audit-log forensics (pandas over JSON-lines), detection verification (replaces the false-green scripts), posture before/after scorecards, RBAC graph analysis, and **headless CI self-test** (`pytest --nbmake`). Setup: JupyterLab 4.x via `uv`, a small `labkit/` helper package (`kubectl_json`, `audit_log`, `falco_events`, `policy_reports`, `expect_denied/allowed/alert`, `positive_control`), jupytext-paired `.py` for diffs, nbstripout pre-commit.

## Modules (full detail in the proposal §4)

M0 foundations/toolchain · M1 identity/RBAC/audit · M2 workload isolation & admission · M3 network · M4 secrets/data · M5 **supply chain** (new) · M6 **runtime detection** (new, Falco) · M7 **nodes/components** (new) · M8 **AI workloads & agents** (new) · M9 assessment & capstone · **M10 agent-driven adversarial testing (purple team)** (new).

Every module runs the loop: **Observe → Detect → Harden → Verify** (positive + negative controls). Each mapped to OWASP K8s 2025 / ATT&CK Containers / CIS.

### M10 — the adversarial agent (what the user specifically asked for)

Purple-team framing: the agent attacks the **throwaway lab cluster only**; the deliverable is a scorecard of **prevented / detected / missed** per technique, measured against M1–M9. Guardrails enforced in code, not the prompt: refuses to run unless context is a `k3d-*` lab cluster; reads an `engagement.yaml` (scope, time box, in-scope techniques, hard network deny-list); egress limited by the lab's own NetworkPolicies + a scope-guard wrapper; uses catalogued published techniques (ATT&CK, Kubenomicon, Stratus Red Team, Kubernetes Goat) and the lab's pinned tooling rather than authoring novel exploits; every action logged and lined up against audit log + Falco. Build order: (a) scripted scenario-runner + scorecard → (c) Stratus/Goat as engine → (b) Agent-SDK free-driving harness. Depends on M6 existing.

## Roadmap

A. **Trust the results** (fix P0 + remaining P1, pin versions incl. Trivy, bump k3s to 1.36.x, audit policy → Metadata for secrets). Self-contained; do this first. ·
B. Notebook foundation (`labkit`, first audit-log-hunting notebook, convert Phase 5 → scorecard, `make verify` + CI). ·
C. Detection (M6 Falco; retrofit Detect steps). ·
D. New surfaces (M5 supply chain, M7 nodes). ·
E. AI workloads (M8). ·
F. Capstone & docs (M9, replace PDF, Linux+macOS README, move design docs to `docs/design/`). ·
G. Adversarial agent (M10) — after C.

## Open decisions for the user

1. CNI: keep flannel + built-in NP controller, or Cilium (L7/FQDN + Hubble + Tetragon path, heavier)?
2. Detector: Falco only, or + Tetragon enforcement?
3. Keep "Phase 1–5" names or move to M0–M10?
4. Single cluster with encryption+audit from the start (removes the Phase 4 rebuild)?
5. Spike needed: does `hostUsers:false` work in this k3d/host kernel before M2 relies on it?
6. M8 scope: CPU-only toy model+MCP server, or also GPU/cloud material?
7. M10 autonomy: scripted (a) / framework (c) / free-driving Agent-SDK (b)? Default start position: assumed pod foothold, or unauthenticated from pod network?

## Loose ends / notes for next session

- **Verify the four fixes on a real cluster** (no Docker here): `make phase1 phase2 phase3 && make cluster-down && make phase4`.
- **Commit attribution model label wobbled** across this session (5.5 vs 4.8) because the session kept reporting different models; the `Co-Authored-By` lines are inconsistent across commits. Harmless; squash or leave as-is.
- A background research subagent produced the brief; its UNVERIFIED list is at the bottom of `threat-landscape-2026-10.md` — confirm those before putting them in learner-facing material.
- User context: this is an authorized personal security lab on throwaway local clusters. The user was (reasonably) frustrated that a couple of replies got truncated mid-task and by the model switching; keep momentum and don't re-litigate that.
