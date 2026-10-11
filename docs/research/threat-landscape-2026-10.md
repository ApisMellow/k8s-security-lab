# Kubernetes Threat Landscape & Guidance, 2024 to Oct 2026: Research Brief for the k3d Attack/Defense Lab

*Compiled 2026-10-11. Primary sources were preferred: the kubernetes.io blog (read from its source in `kubernetes/website`), the `kubernetes/kubernetes` `official-cve-feed` issues, GitHub Security Advisories (GHSA) and release pages, CISA and the CNCF. Vendor research blogs (Wiz, Unit 42, Aikido, Oligo, Horizon3) are used for exploitation detail. Claims that rest only on secondary or aggregator sources are marked **(secondary)**. Claims I could not confirm are marked **UNVERIFIED**.*

Note: kubernetes.io, discuss.kubernetes.io, owasp.org, attack.mitre.org and cisecurity.org could not be fetched directly from this environment. Those facts were checked through the `kubernetes/website` GitHub source, GitHub issues and advisories, or search results that quote those pages.

---

## 0. Executive summary: what changed since a "2023-era" k8s security lab

1. **ingress-nginx is gone.** IngressNightmare (Mar 2025) was followed by more config-injection CVEs in Feb–Mar 2026. The project was then **retired on 2026-03-24**, and the repo is archived. Teach Gateway API, and treat ingress-nginx as a "legacy, unpatchable component" scenario.
2. **"Read-only" RBAC is not read-only.** `nodes/proxy` GET lets you exec into any pod through the kubelet WebSocket (early 2026). The project's answer was "won't fix" (no CVE). Fine-grained kubelet authz went **GA in v1.36** so that monitoring tools no longer need `nodes/proxy`.
3. **Core hardening primitives went GA.** These include user namespaces (`hostUsers: false`, GA v1.36), MutatingAdmissionPolicy (GA v1.36), external SA-token signing (GA v1.36), Pod Certificates and ClusterTrustBundles (GA v1.37), structured authn (GA v1.34), anonymous-auth endpoint restriction (GA v1.34), and SupplementalGroupsPolicy (GA v1.35). The `gitRepo` volume is permanently disabled (v1.36).
4. **The container runtime is the hot zone.** It saw the runc triple escape (Nov 2025), a containerd image-LABEL → host-root command execution bug (CVE-2026-53488, Jun 2026), several containerd CRI checkpoint-restore criticals (Jun–Sep 2026), and the kernel "Copy Fail" LPE/escape (CVE-2026-31431, in CISA KEV May 2026).
5. **Supply chain attacks now hit *security tools*.** Trivy itself was compromised by TeamPCP in Mar 2026 (CVE-2026-33634). The same campaign shipped a **Kubernetes wiper DaemonSet**. Earlier came tj-actions (Mar 2025) and Shai-Hulud 1 and 2 (Sep and Nov 2025). Your lab uses Trivy, so this is directly relevant.
6. **Policy engines moved to CEL.** Kyverno graduated in the CNCF (2026-03-24). Its CEL policy types (ValidatingPolicy, ImageValidatingPolicy, and others) went v1 in 1.17 (Feb 2026), and ClusterPolicy is deprecated. The current release is **1.19.1** (2026-09-10).
7. **AI workloads are the new initial-access surface.** Examples: ShadowRay 2.0 (Nov 2025), vLLM pickle RCEs, NVIDIA Container Toolkit escapes, Triton chain, Langflow in KEV, MCP-server-for-Kubernetes command injections, and the OWASP Top 10 for Agentic Applications (Dec 2025).

---

## 1. Notable CVEs and incidents, 2024–2026 (lab-relevant)

### 1.1 Kubernetes-project CVEs: the official feed
Source: the `official-cve-feed` label on kubernetes/kubernetes — https://github.com/kubernetes/kubernetes/issues?q=label%3Aofficial-cve-feed . The only *open* (unfixed) item is CVE-2020-8554, which the 1.36 `externalIPs` deprecation addresses.

| CVE | Component / summary | Date | Versions / fix | Lab value |
|---|---|---|---|---|
| **CVE-2024-10220** | kubelet `gitRepo` volume → arbitrary command exec outside the container (hooks in the cloned repo). CVSS 8.1 | Nov 2024 | Affects ≤1.28.11, 1.29.0–1.29.6, 1.30.0–1.30.2. Fixed 1.28.12/1.29.7/1.30.3/1.31.0 | High (classic). See also the gitRepo removal below |
| **CVE-2025-1767** | `gitRepo` volume can reach *other pods'* local repos on the same node. 6.5 | 2025-03-13 | All versions; **no fix**. Mitigate by blocking gitRepo with admission policy. v1.33 disabled the in-tree driver by default; **v1.36 permanently disabled it** | Policy exercise |
| **CVE-2024-9042** | Windows-node kubelet command injection via `nodes/*/logs/query` | Jan 2025 | Windows nodes only | Low for k3d (no Windows) |
| **CVE-2025-0426** | kubelet read-only checkpoint API → node DoS. 6.2 | Feb 2025 | Fixed 1.32.2/1.31.6/1.30.10/1.29.14 | Medium |
| **CVE-2025-1974** + CVE-2025-1097/1098/24513/24514 ("IngressNightmare", Wiz) | ingress-nginx admission webhook reachable from the pod network → nginx config injection → RCE in the controller. The controller can read **all cluster Secrets** by default. 9.8 | 2025-03-24 | Fixed in controller v1.11.5 / v1.12.1. Mitigation: disable the admission webhook. https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/ | **Very high** |
| CVE-2025-4563 | NodeRestriction lets a node bypass DRA authz when creating mirror pods | Jun 2025 | Only when DRA is enabled | Low |
| **CVE-2025-5187** | Nodes can delete themselves by adding an OwnerReference (NodeRestriction gap). 6.7 | Aug 2025 | Patched 1.31/1.32/1.33 lines | Medium (node-credential abuse) |
| CVE-2025-7342 | Kubernetes Image Builder Windows VM images use default creds | Aug 2025 | — | Low |
| CVE-2025-7445 | secrets-store-sync-controller logs SA tokens | Sep 2025 | — | Medium (token-in-logs hunt) |
| CVE-2025-9708 | Kubernetes C# client cert validation | Sep 2025 | — | Low |
| CVE-2025-13281 | Portworx half-blind SSRF in kube-controller-manager | Dec 2025 | — | Low |
| CVE-2025-14269 | Headlamp credential caching with Helm enabled | Dec 2025 | — | Low/Med |
| **CVE-2026-1580, -24512, -24513, -24514, CVE-2025-15566** | ingress-nginx annotation config injections (`auth-method`, `path`, `auth-proxy-set-headers`), auth-url bypass, admission DoS. 1580 = 8.8 | 2026-02-02/06 | Fixed v1.13.7 / v1.14.3 (GitLab advisory DB: https://advisories.gitlab.com/golang/k8s.io/ingress-nginx/CVE-2026-1580/) | High |
| **CVE-2026-3288**, **CVE-2026-4342** | ingress-nginx `rewrite-target` and comment-based config injection | 2026-03-11, 2026-03-19 | Last fixes before retirement | High |
| CVE-2026-3864 / -3865 | CSI NFS/SMB driver `subDir` path traversal deletes unintended dirs | Mar–Apr 2026 | — | Low |
| **CVE-2026-2270** | **StatefulSet controller confused deputy.** Write access to StatefulSet + ControllerRevision in your own namespace lets you create a pod in **another namespace**. You need the UID of a StatefulSet in the victim namespace to survive GC. CVSS 5.9 | Opened 2026-09-14, fixed 2026-09-23 | kube-controller-manager ≤1.34.11, ≤1.35.8, ≤1.36.4, 1.37.0. Fixed 1.34.12/1.35.9/1.36.5/1.37.1. https://github.com/kubernetes/kubernetes/issues/142097 | **High** (new, multi-tenant RBAC lesson) |
| CVE-2026-19444 | `kubectl cp` path traversal on Windows clients | Sep 2026 | Fixed kubectl 1.34.12/1.35.9/1.36.5/1.37.1 (secondary for the versions) | Low |
| CVE id UNVERIFIED (issue #142098) | Subpath symlinking on Windows nodes → NTLM coercion | Sep 2026 | Windows nodes | Low for k3d |

**Records corrected 2026-06-01.** The SRC re-marked CVE-2020-8561 (webhook redirect), CVE-2020-8562 (proxy DNS TOCTOU) and CVE-2021-25740 (Endpoints cross-namespace) as **unfixed, all versions affected**, so scanners will now flag them. Source: https://kubernetes.io/blog/2026/05/26/reconciling-unfixed-kubernetes-cves/ (date from the post source). This makes a good "scanner noise vs real risk" discussion.

### 1.2 ingress-nginx retirement
- 2025-11-11: retirement announced, with best-effort maintenance until March 2026 — https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/
- 2026-01-29: Steering + Security Response Committee statement. It says ingress-nginx is used by about half of cloud-native environments, there will be no fixes after retirement, and you should migrate to Gateway API — https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/
- **2026-03-24: retired.** GitHub repo archived the same day. "No further releases, no bugfixes, and no updates to resolve any security vulnerabilities" (v1.36 release blog). ingress2gateway v1.0 is the migration tool. Some vendors still backport fixes (SUSE Rancher Prime until Dec 2027).
- **k3d note:** k3s ships **Traefik** by default, not ingress-nginx. An IngressNightmare exercise must install a pinned old ingress-nginx chart (e.g. controller v1.11.4 or v1.12.0) on purpose.

### 1.3 Kubernetes Dashboard archived
`kubernetes/dashboard` was **archived 2026-01-21**, with "no longer maintained" in the README. Headlamp is the successor (kubernetes.io blogs 2026-06-01 and 2026-07-13). Exposed-dashboard attack scenarios now describe an unmaintained component.


### 1.4 Container runtime and kernel escapes (advisory summaries)
All are container-breakout / host-compromise class issues. Treat them as "patch the runtime and kernel" and "defense in depth with user namespaces + seccomp" lessons, not as exploit walkthroughs.

| ID | Component / class | Date | Severity | Fixed versions | Source |
|---|---|---|---|---|---|
| **CVE-2024-21626** "Leaky Vessels" | runc, leaked file descriptor breakout | 2024-01-31 | High | runc 1.1.12 | GHSA-xr7r-f8xq-vfvv |
| CVE-2024-23651/-23652/-23653 "Leaky Vessels" | BuildKit build-time races / mount / policy bypass | 2024-01-31 | High | BuildKit 0.12.5 **(from memory, not re-fetched — verify)** | Snyk Leaky Vessels |
| **CVE-2025-31133 / -52565 / -52881** (the "runc trio") | runc, three independent breakout/DoS classes (masked paths, `/dev/console` bind mount, procfs write redirect). Disclosed together | 2025-11-05 (all three GHSA) | High | runc 1.2.8, 1.3.3, 1.4.0-rc.3 | https://github.com/opencontainers/runc/security/advisories ; CNCF overview https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/ |
| CVE-2026-41579 | runc, malicious image `/dev` symlink → limited host write | 2026-06-13 | Low | runc 1.4.3 / 1.5.0-rc3 (GHSA-xjvp-4fhw-gc47) | runc advisories |
| **CVE-2026-53488** | containerd CRI: image-config LABEL flows to a host-root command execution path on image pull | 2026-06-18 | Critical (8.8–9.4 depending on source) | containerd 1.7.33, 2.0.10, 2.1.9, 2.2.5, 2.3.2 | GHSA-xhf5-7wjv-pqxp |
| CVE cluster, containerd CRI checkpoint-restore (GHSA-p7v4-vr35-mj6f, -33vj-92qq-66hc, -cvxm-645q-p574, -rgh6-rfwx-v388) | security-context bypass, CDI annotation smuggling, image-tag poisoning, host file read via symlink | 2026-06 to 2026-09 | Critical/High | see containerd advisories | https://github.com/containerd/containerd/security/advisories |
| GHSA-fqw6-gf59-qr4w (CVE id not confirmed) | containerd user-ID handling → `runAsNonRoot` evasion | 2026-05-20 | Moderate | containerd advisories | same |
| **Kernel "Copy Fail", CVE-2026-31431** | Linux kernel `crypto/algif_aead` LPE; usable as a container escape because the kernel is shared | Published 2026-04-22; **added to CISA KEV 2026-05-01 (actively exploited)** | High | distro kernels (5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12, 7.0+) | Kudelski / UC Berkeley / CISA KEV. Mitigate by blacklisting `algif_aead` and restricting `AF_ALG` via seccomp |

The v1.37 "Rootless mode" blog is a good teaching reference: it explicitly lists CVE-2022-0811 (cr8escape), CVE-2023-27561, CVE-2024-10220, CVE-2025-31133 and CVE-2026-53488 as the breakout history that user namespaces + rootless node components mitigate — https://kubernetes.io/blog/2026/09/04/kubernetes-v1-37-rootless-beta/

### 1.5 NVIDIA Container Toolkit / GPU
| CVE | Summary | Date | Fixed |
|---|---|---|---|
| **CVE-2024-0132** (Wiz) | NVIDIA Container Toolkit TOCTOU container escape. 9.0 | Sep 2024 | Toolkit 1.16.2, GPU Operator 24.6.2 **(secondary)** |
| **CVE-2025-23359** | Bypass of the 2024-0132 patch (TOCTOU). 8.1 | Feb 2025 | Toolkit 1.17.4, GPU Operator 24.9.2 |
| **CVE-2025-23266 "NVIDIAScape"** (Wiz) | OCI hook (`enable-cuda-compat`) inherits container env → privileged execution. 9.0 | Jul 2025 | Toolkit 1.17.8, GPU Operator 25.3.1. Affects Toolkit ≤1.17.7 (CDI mode <1.17.5) | https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape |

k3d has no GPU, so cover these as discussion/architecture, or simulate the pattern with a privileged OCI-hook analogue.

### 1.6 GitOps / packaging
- **Argo CD CVE-2025-55190** (project API token exposes repository credentials; a token with project `get` reads repo/cluster creds). CVSS 9.9–10. Fixed 2.13.9 / 2.14.16 / 3.0.14 / 3.1.2. Averlon/Wiz DBs.
- **Argo CD 2026 wave** (GHSA list, https://github.com/argoproj/argo-cd/security/advisories): GHSA-3v3m-wc6v-x4x3 Secret extraction via ServerSideDiff — **Critical, 2026-05-01**; a set of **Critical repo-server command/file-read issues published 2026-10-07** (Kustomize Helm config-home exec, Kustomize remote-ref exec, Jsonnet file read, PreDelete/PostDelete hook AppProject bypass); stored XSS dev→admin (GHSA-h98r, High, 2026-05-13).
- **Argo CD Helm chart CVE (GHSA-47m3-95c7-g2g8)**, "network policies securing repo-server are not installed by default → RCE", High, 2026-06-29; fix = chart v10.0.0 (adds default NetworkPolicies). Good NetworkPolicy teaching hook.
- **Helm CVE-2025-53547**: a crafted `Chart.yaml` + symlinked `Chart.lock` causes local code execution during `helm dependency update`. 8.5. Fixed **Helm 3.18.4** (no longer follows symlinks). NVD. *(Helm 4 GA status not confirmed — **UNVERIFIED**.)*
- **Image builders**: Google **archived kaniko in June 2025**; a Chainguard fork continues security-only maintenance (images not public), so `gcr.io/kaniko-project/executor` is unmaintained. thenewstack.io.

---

## 2. Kubernetes release security changes (1.30 → 1.37), with feature state
Read from the release-blog sources in `kubernetes/website`. Release dates: **1.30** 2024-04-17, **1.31** 2024-08-13, **1.32** 2024-12-11, **1.33** 2025-04-23, **1.34** 2025-08-27, **1.35 "Timbernetes"** 2025-12-17, **1.36 "Haru"** 2026-04-22, **1.37 "Garhwal"** 2026-08-26. CIS/benchmark and most managed providers now track ~1.32–1.35.

**Admission / policy**
- **ValidatingAdmissionPolicy (VAP, CEL): GA in v1.30** (KEP-3488). This is the in-tree CEL admission you should teach first. https://github.com/kubernetes/website/tree/main/content/en/blog/_posts/2024/validating-admission-policy-ga
- **MutatingAdmissionPolicy (CEL, JSON Patch/SSA): alpha 1.32 → beta 1.34 → GA v1.36** (KEP-3962). Native alternative to mutating webhooks.
- **Manifest-based admission control config**: alpha 1.36 → **beta 1.37** (KEP-5793). Admission webhooks/CEL policies load from on-disk manifests, enforced from API-server startup and protecting the API-based admission resources from tampering. Strong "bootstrap gap" lesson.

**Authn / authz / tokens**
- **Structured authentication config** (multiple JWT issuers, CEL): beta 1.30 → **GA v1.34** (KEP-3331).
- **Structured authorization config** (ordered authorizers, CEL webhook match): beta 1.30 → **GA v1.32** (KEP-3221).
- **Restrict anonymous auth to named endpoints** (`/healthz` etc.): 1.31/1.32 → **GA v1.34** (KEP-4633). Directly counters the anonymous-auth cryptojacking pattern.
- **Finer-grained authorization on label/field selectors**: 1.31 → **GA v1.34** (KEP-4601). Enables per-node least privilege.
- **Bound SA token improvements** (JTI, node binding): **GA v1.33** (KEP-4193). Node-bound tokens reduce token-theft blast radius.
- **External SA-token signing**: beta 1.34 → **GA v1.36** (KEP-740).
- **Fine-grained kubelet API authorization**: alpha 1.32 → beta 1.33 → **GA v1.36**, gate locked on (KEP-2862). Removes the need to grant `nodes/proxy` to monitoring. https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/
- **Constrained impersonation**: alpha 1.35 → **beta v1.36** (KEP-5284). Impersonation stops being all-or-nothing.
- **kubelet image-credential-provider SA tokens** (short-lived, audience-bound, no node-level Secrets): 1.33 → beta 1.34 → (KEP-4412). Token-for-image-pulls is **beta as of 1.34**. The v1.36 GA item, external signing, is a different KEP.
- **Ensure-secret-pulled-images** (kubelet verifies pull creds for cached images, closes the shared-node image-cache hole): alpha 1.33 → **beta v1.35**, gate `KubeletEnsureSecretPulledImages` (KEP-2535).
- **CSI SA tokens via `secrets` field (not `volume_context`, to avoid log leakage)**: **beta v1.35** (KEP-5538).
- **Pod Certificates + ClusterTrustBundles** (native mTLS identity, kubelet-issued, node-restricted at admission): PodCert alpha 1.34 → beta 1.35; CTB beta 1.33; **both GA v1.37** (KEP-4317, KEP-3257).

**Workload / node isolation**
- **User namespaces for pods (`hostUsers: false`)**: beta-on-by-default 1.33 → **GA v1.36** (KEP-127). The single biggest new defense-in-depth primitive — maps container root to an unprivileged host user.
- **KubeletInUserNamespace / rootless mode**: **beta v1.37** (KEP-2033). Node components themselves run unprivileged. Distinct from `hostUsers: false`.
- **AppArmor support (via `securityContext.appArmorProfile` fields)**: **GA/stable in v1.31** (KEP-24). Replaces the old annotations.
- **ProcMount option**: on-by-default beta v1.33 (KEP-4265).
- **SupplementalGroupsPolicy (`Strict`)**: beta 1.33 → **GA v1.35** (KEP-3619). Drops implicit image `/etc/group` memberships.
- **SELinux volume relabel speed-up / `seLinuxMount`**: beta → **GA v1.36** (KEP-1710); note the warning about shared-volume breakage.
- **Restricted PSS now forbids remote probes (`host` in probes)**: alpha v1.34 (KEP-4940).
- **PSA (Pod Security Admission)** remains the built-in replacement for PSP; no major change in this window beyond the probe tightening above.

**Volumes / images / supply chain primitives**
- **Image volumes (OCI artifact/image as a read-only volume)**: alpha 1.31 → beta 1.33 → **GA v1.36** (KEP-4639). Needs containerd ≥2.1. Good for shipping models/config as signed OCI artifacts.
- **`gitRepo` volume**: in-tree driver removed v1.33, **permanently disabled v1.36** (KEP-5040).
- **`Service.spec.externalIPs` deprecated v1.36** (the CVE-2020-8554 MITM field), removal planned v1.43 (KEP-5707).
- **Static pods can no longer reference Secrets/ConfigMaps (v1.37)**; `PreventStaticPodAPIReferences` gate removed.

**KMS / encryption at rest**
- **KMS v2: GA since v1.29** (your lab's encryption-at-rest should use KMS v2 / AES-GCM). **UNVERIFIED for any 1.30+ change** — no KMS KEP appeared in the 1.30–1.37 security sections I read, so treat KMS v2 as stable-and-unchanged.
- **v1.37 beta: identify and delete undecryptable resources** via the API (KEP-3926) — useful when an encryption key is lost.

**DRA (Dynamic Resource Allocation)** core went **GA in v1.34**, with AdminAccess and other sub-features GA in v1.36. Relevant to GPU/AI scheduling and to CVE-2025-4563.

---

## 3. Frameworks and guidance (current status)

- **OWASP Kubernetes Top 10 — 2025 edition is live** (repo has a `2025/en/src` tree; the site shows "2025 Top 10 Risks now available"). List: K01 Insecure Workload Configurations, K02 Overly Permissive Authorization, K03 Secrets Management Failures, K04 Lack of Cluster-Level Policy Enforcement, K05 Missing Network Segmentation, K06 Overly Exposed Components, K07 Misconfigured/Vulnerable Cluster Components, K08 Cluster-to-Cloud Lateral Movement, K09 Broken Authentication, K10 Inadequate Logging & Monitoring. Note vs 2022: the old standalone "Supply Chain Vulnerabilities" category is folded in; Cluster-to-Cloud lateral movement is explicit. Exact 2025 publication date **UNVERIFIED** (couldn't read commit dates). https://owasp.org/www-project-kubernetes-top-ten/
- **OWASP Top 10:2025 (web app)** is a separate project; its new A03 is "Software Supply Chain Failures." Don't conflate.
- **OWASP Top 10 for LLM Applications** (2025) and **OWASP Top 10 for Agentic Applications 2026** (published **2025-12-09**, categories ASI01–ASI10, ASI01 = Agent Goal Hijack). Both from the OWASP GenAI Security Project. Relevant to section 4.
- **MITRE ATT&CK v19 (2026-04-28)**: the Enterprise matrix **split "Defense Evasion" into "Stealth" (TA0005, keeps the old ID) and "Defense Impairment" (TA0112)**. Detection rules still tagged "Defense Evasion" can break. The **Containers matrix** (attack.mitre.org/matrices/enterprise/containers/) remains ~10 tactics / ~38 techniques; a version-specific Containers changelog was **not verified**. v19.1 also exists. https://attack.mitre.org/resources/updates/updates-april-2026/
- **Microsoft Threat Matrix for Kubernetes**: last substantive release is **v3 (Dec 2022)** at aka.ms/KubernetesThreatMatrix. No 2025/2026 Kubernetes-matrix update found (a Sep 2026 Microsoft matrix is for *cloud web apps*, a different domain). Microsoft's **"Understanding the threat landscape for Kubernetes and containerized assets" (2025-04-23)** is the current narrative report (Storm-1977, 51% inactive workload identities).
- **CIS Kubernetes Benchmark**: newest is **v2.0.1** (covers k8s 1.34/1.35), per CIS June 2026 update. AKS/EKS benchmarks v2.0 / v1.8 cover 1.32–1.34. **kube-bench v0.16.0 (2026-08-05)** supports `cis-1.11` (added v0.13.0) and `cis-1.12` (added v0.15.0); no `2.0.1` profile confirmed in kube-bench yet — **verify the profile mapping** when you wire it up. https://github.com/aquasecurity/kube-bench/releases
- **NSA/CISA Kubernetes Hardening Guide**: still **v1.2 (Aug 2022)**. No newer version found. Treat as dated but still structurally useful.
- **NIST SP 800-190**: still the **2017 original**; no Rev 1 draft found (**UNVERIFIED** that one exists).
- **CNCF Cloud Native Security Whitepaper**: current is **v2 (May 2022)**. Newer TAG Security & Compliance work: the **Cloud Native Security Controls Catalog**, with a **2026 release** mapping controls to NIST 800-53 — https://contribute.cncf.io/blog/2026/06/10/cloud-native-security-controls-catalog
- **SLSA v1.2 (Nov 2025)**: adds the **Source Track** (backwards-compatible with v1.1). Build Environment and Dependency tracks are in development. https://slsa.dev/blog/2025/11/announce-slsa-v1.2
- **CNCF Certified Kubernetes AI Conformance**: launched **Nov 2025** (KubeCon NA). Requirements ("KARs") include accelerator mgmt, gang scheduling, inference networking, observability and security; self-assessed, 1-year validity, automated tests planned for 2026. Grew 18→31 certified platforms by KubeCon EU 2026. https://www.cncf.io/announcements/2025/11/11/cncf-launches-certified-kubernetes-ai-conformance-program-to-standardize-ai-workloads-on-kubernetes/

---

## 4. AI/LLM workloads on Kubernetes

- **ShadowRay / ShadowRay 2.0** — **CVE-2023-48022** (Ray dashboard/jobs API, no auth; disputed by Anyscale as "intended," so unpatched, 9.8). The original ShadowRay (Oligo, 2024) and **ShadowRay 2.0 (Oligo, Nov 2025)** turn exposed Ray clusters into a **self-replicating cryptomining + DDoS botnet**, >230,000 exposed Ray servers seen. Still the canonical "exposed AI control plane" lesson. https://www.oligo.security / BleepingComputer / TheRegister 2025-11-18.
- **vLLM pickle/deserialization RCEs**: **CVE-2025-32444** (Mooncake ZeroMQ pickle, 10.0, fixed 0.8.5); **CVE-2025-47277** (PyNcclPipe `pickle.loads`, 0.6.5–0.8.4). A later **CVE-2026-22778** (pre-auth RCE via crafted video URL to multimodal endpoint, 9.8, fixed 0.14.1) is **secondary/UNVERIFIED**. Teaches model-server pickle risk.
- **NVIDIA Triton chain**: **CVE-2025-23319/-23320/-23334** (Wiz, Aug 2025) → unauth RCE; fixed in **25.07**.
- **Model file deserialization**: pickle in `.bin`/`.pt`/`.ckpt` runs code on load; mitigate with **safetensors**, and scan with `picklescan` / ModelScan. (General guidance; no single CVE.)
- **MCP servers / AI agents in-cluster** — command-injection CVEs in Kubernetes MCP servers: **CVE-2025-53355** (`mcp-server-kubernetes` `execSync`, fixed 2.5.0), **CVE-2025-66404** (`execinpod` metachars, fixed 2.9.8), **CVE-2026-39884** (`port_forward` flag injection, ≤3.4.0), and **CVE-2025-59377** (feiskyer `mcp-kubernetes-server`, `shell=True`, OS cmd injection even in read-only mode, 9.8). Excellent new lab material: "the AI agent's tool server is the vulnerability."
- **Operation campaigns**: Sysdig "Operation Bizarre Bazaar" (Dec 2025–Jan 2026, 35k+ sessions vs exposed AI infra); **Langflow** CVE-2026-9198 (9.8 RCE) and CVE-2026-55255 added to **CISA KEV (Jul–Aug 2026)** — the first AI-agent platform in KEV; ~175k unauthenticated Ollama instances reported. Mostly vendor/secondary; verify in CISA KEV before citing as fact.
- **Kubernetes-native AI isolation**: the SIG Apps **Agent Sandbox** project (`kubernetes-sigs/agent-sandbox`, Sandbox CRD, gVisor/Kata runtimes, scale-to-zero) is the upstream answer to running untrusted agent code. https://kubernetes.io/blog/2026/03/20/agent-sandbox/
- **OWASP Top 10 for LLM 2025** and **Agentic Applications 2026** (see §3).

---

## 5. Supply chain

- **Sigstore / cosign v3** (and v3.1.x; current **v3.1.3**, 2026-08-06, fixes a legacy-bundle verification bypass GHSA-fx35-mq7g-6g98). v3 makes the **new Sigstore bundle format the default** for signing (`--new-bundle-format=false` to opt out), routes signing through `sigstore-go`, logs to **Rekor v2**, and requires `--bundle`. v4 (will remove deprecated functionality) not yet released. https://blog.sigstore.dev/cosign-3-0-available/ ; https://github.com/sigstore/cosign/releases
- **Kyverno image verification**: legacy `verifyImages` in ClusterPolicy; the CEL-era replacement is **ImageValidatingPolicy** (v1 in Kyverno 1.17). Use it for cosign/Notary signature + attestation checks.
- **sigstore policy-controller** (ClusterImagePolicy admission): current **v0.15.1 (2026-03-26)**. **Connaisseur** is **not archived** (active repo), remains an alternative admission verifier.
- **SBOM/VEX / provenance**: SLSA v1.2 Source Track (§3); SPDX 3.x / CycloneDX + OpenVEX; image provenance attestations via cosign attest + Rekor. Trivy generates **KBOM** (Kubernetes BOM) and consumes VEX.
- **tj-actions/changed-files — CVE-2025-30066** (2025-03): action compromised to dump CI secrets to logs; chained from **reviewdog/action-setup — CVE-2025-30154**. Both added to **CISA KEV 2025-03-18**. Fix: v46.0.1 and pin actions to full commit SHAs. https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- **Shai-Hulud npm worm** — v1 (Sep 2025, 500+ packages) and **"Second Coming" / 2.0 (late Nov 2025)**: self-propagating npm worm that runs in `preinstall`, harvests cloud creds (AWS/GCP/Azure) and GitHub tokens with TruffleHog, registers hosts as a self-hosted runner named `SHA1HULUD`, and has a wiper fallback. 600–800 packages, 25k+ repos. IoCs: `setup_bun.js`, `bun_environment.js`. Intel 471 / Cycode / Invicti.
- **Trivy supply-chain compromise — CVE-2026-33634 (GHSA-69fq-xp46-6x23, Critical)**, attributed to **TeamPCP**, 2026-03-19→23: a malicious **Trivy v0.69.4** binary, hijacked tags across `aquasecurity/trivy-action` (76/77 tags) and `aquasecurity/setup-trivy`, and malicious Docker Hub images v0.69.5/0.69.6. The injected code swept SSH keys, cloud creds, **Kubernetes tokens** and Docker configs from CI runners. Safe: Trivy 0.69.2/0.69.3, trivy-action v0.35.0. IoC: `tpcp-docs-*` repos. **This directly affects your lab's Trivy usage.** https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- **TeamPCP Kubernetes wiper (CanisterWorm)** — the same actor's payload deploys a **privileged DaemonSet in `kube-system`** that tolerates all taints and destroys nodes matching Iran's locale, with a persistent backdoor DaemonSet elsewhere (Aikido/BleepingComputer, Mar 2026). Downstream: stolen tokens hit LiteLLM's PyPI pipeline and Checkmarx KICS actions. Mostly **secondary**; a vivid "malicious DaemonSet + full SHA pinning" lesson.
- **Malicious images / typosquatting**: the canonical dataset is still Sysdig's 2022 study (1,652 malicious of ~250k Docker Hub images; crypto-miners + embedded secrets; typosquatting). No fresher comprehensive Helm/Artifact Hub typosquat study found — **UNVERIFIED** for 2025/2026 Helm-specific numbers.

---

## 6. Runtime detection tooling (for a local k3d lab)

| Tool | Current | Notes for k3d |
|---|---|---|
| **Falco** | **0.45.0 (2026-09-21)** | eBPF (modern_ebpf) works on a modern kernel without a kernel module — ideal for k3d. **Breaking removals to know**: 0.44.0 removed gRPC output, gVisor engine, and the legacy BPF probe; 0.45.0 removed the `container_engines` config key. `falcosidekick` routes alerts; **Falco Talon** is the response engine (part of falcosecurity, Helm chart ~0.1.x; last activity Apr 2026 **(secondary)**). Best first choice for a detection lab. https://github.com/falcosecurity/falco/releases |
| **Tetragon** (Cilium) | **1.7.1 (2026-08-25)** | eBPF, `TracingPolicy` CRDs, in-kernel **enforcement** (kill/override). 1.7 added CEL-in-BPF, `matchParentBinaries`, fentry sensor. Great for "detect + block" exercises; heavier than Falco. https://github.com/cilium/tetragon/releases |
| **KubeArmor** | **1.7.5 (2026-09-11)**, 1.7.6 RCs in Oct | LSM-based (AppArmor/BPF-LSM) **inline enforcement** of process/file/network policy. Pairs well with the AppArmor-GA lesson. |
| **Tracee** (Aqua) | latest 0.24.x (exact release date UNVERIFIED) | eBPF detection + `suspicious_syscall_source`, in-kernel filtering; **Rego signatures removed** (0.23.0). Good for syscall-level teaching. |

Recommendation for the lab: **Falco (modern eBPF) + falcosidekick** as the baseline detector, then **Tetragon or KubeArmor** for a "runtime enforcement / blocking" module. All run on a single-node k3d cluster on a recent kernel.

---

## 7. Policy engines

- **Kyverno** — graduated in the CNCF **2026-03-24**. Current **1.19.1 (2026-09-10)**. The big shift: **CEL-based policy types reached v1 (GA) in 1.17 (Feb 2026)** — `ValidatingPolicy`, `MutatingPolicy`, `GeneratingPolicy`, `ImageValidatingPolicy`, `DeletingPolicy`, `PolicyException`, plus Namespaced variants. **`ClusterPolicy`/`CleanupPolicy` are deprecated** (maintenance-only through ~1.19, removal targeted ~1.20). Migration map: validate→ValidatingPolicy, mutate→MutatingPolicy, generate→GeneratingPolicy, verifyImages→ImageValidatingPolicy, CleanupPolicy→DeletingPolicy. **`kyverno test`** (CLI) and `kyverno-json` remain for unit-testing policies in CI. Teach both ClusterPolicy (legacy, still common) and the new CEL types. CNCF: https://www.cncf.io/blog/2026/02/18/announcing-kyverno-1-17/
- **OPA Gatekeeper** — current **v3.23.1 (2026-08-27)**. Actively generates/managed **ValidatingAdmissionPolicies** from constraints (CEL via `K8sNativeValidation`), `gator` CLI (`gator test/bench/policy`) for offline testing, mutation support. Still the Rego option. https://github.com/open-policy-agent/gatekeeper/releases
- **In-tree ValidatingAdmissionPolicy / MutatingAdmissionPolicy** (§2) — teach these first; no controller to install, CEL, GA. Then show Kyverno/Gatekeeper for richer features (generation, image verification, reporting).

---

## 8. Attack / education tooling (current state)

| Tool | Status | Use |
|---|---|---|
| **kubeletctl** (cyberark) | Active | Enumerate/abuse the kubelet 10250 API, pull SA tokens, run across pods. Core for the kubelet / `nodes/proxy` exercises |
| **peirates** (InGuardians) | Active (not archived) | In-pod privesc/escape toolkit; container image tag ~v1.1.32 |
| **kube-hunter** (Aqua) | **Deprecated** — "not under active development," points to Trivy | Mention only; use Trivy k8s / kubescape instead |
| **BOtB** (break-out-the-box) | Appears active, no release shown | Container breakout/auto-exploit; older |
| **CDK** (cdk-team) | Active | In-container recon + exploit (escapes, cloud-metadata, RBAC abuse); includes CVE-2026-31431 "copy-fail" module. Good "post-initial-access" toolkit |
| **Kubernetes Goat** (madhuakula) | Active, **22 scenarios** | Deliberately vulnerable cluster; docs mention KIND/K3s (k3d works). Best turnkey attack playground |
| **ControlPlane simulator** | Active ("Maintenance"), **AWS-based** (Terraform/Packer), V2 redesign | Not local — note the AWS requirement; less suited to a pure-local k3d lab |
| **Bust-a-Kube** | Older/mostly static | Deliberately vulnerable cluster; dated |
| **KubeHound** (DataDog) | Active, **v1.6.7 (2025-11-14)** | BloodHound-style **attack-path graph**; v1.6.4 added MITRE ATT&CK TTP mapping; Jupyter notebook support. Excellent "visualize the attack graph" module |
| **rbac-police** (Palo Alto) | **Archived 2025-04-10** | Rego RBAC risk policies; still usable but unmaintained |
| **KubiScan** (CyberArk) | Active | Find risky RBAC subjects/roles, risky pods/tokens |
| **kubectl-who-can** (Aqua) | Active | "Who can `verb resource`" RBAC lookups |
| **rakkess** | (not re-checked) **UNVERIFIED** | RBAC access matrix (`kubectl access-matrix`) |
| **Stratus Red Team** (DataDog) | Active | Has a Kubernetes platform with k8s.* techniques (exact list at stratus-red-team.cloud; not enumerated here). Detonate-and-detect |
| **Kubenomicon** (Graham Helton) | Active site | Offensive threat matrix for k8s with exploit/remediation walkthroughs; inspired by Microsoft's matrix. Great curriculum scaffold |
| **KubeHound / Kubescape / Trivy / kube-bench** | see §6/§9 | Defense-side |

---

## 9. Real-world attack patterns observed 2024–2026

1. **Cryptojacking via exposed/anonymous control plane.** DERO (Wiz, 2024) and Kinsing/TeamTNT families target **anonymous-auth API servers** and **anonymous kubelets**, then deploy miner **DaemonSets** with benign names (`k8s-device-plugin`, `pytorch-container`). RBAC Buster (Aqua, 2023) creates a `system:controller`-style ClusterRole for persistence. Lesson: disable anonymous auth (now endpoint-scoped, §2), lock kubelet authz.
2. **`nodes/proxy` GET → pod exec (2026).** A SA with only read `nodes/proxy` can open a kubelet `/exec` WebSocket (the handshake GET maps to RBAC `get`, with no `create` check) and run commands in any pod on reachable nodes — and it generates **no Kubernetes audit log**. Project response: "won't fix," no CVE. ~69 popular charts (Prometheus, Grafana, Datadog) request `nodes/proxy`. Mitigation: fine-grained kubelet authz (GA v1.36). Horizon3.ai (2026-02-27) H3-2026-0002; Graham Helton.
3. **Cloud credential theft from pods via IMDS.** A compromised/SSRF-able pod reaches the node **IMDS** and steals the node role. Mitigate with IMDSv2 + **hop limit 1** and NetworkPolicy to 169.254.169.254. DataDog Cloud Security Atlas.
4. **EKS Pod Identity / IRSA and access-entry abuse.** Treat `eks:CreateAccessEntry` / `eks:AssociateAccessPolicy` as highly privileged; `AmazonEKSEditPolicy` is **not** a security boundary (multiple privesc paths to cluster-admin). Wiz, 2024–2025.
5. **Service-account token theft / over-privileged tokens.** Still the top lateral-movement primitive; node-bound tokens (v1.33) and short-lived projected tokens reduce it. Also CVE-2025-7445 (tokens leaked to logs).
6. **Compromised cloud identities → managed-cluster takeover.** Storm-1977 password-spraying vs AKS (education sector), 200+ containers repurposed for mining. Microsoft, 2025-04-23. 51% of workload identities inactive.
7. **Exposed AI infra as initial access** (§4): Ray, Ollama, Langflow, Triton, vLLM, MCP servers.
8. **Supply-chain → cluster** (§5): poisoned CI actions and a poisoned *scanner* (Trivy) leading to a destructive in-cluster DaemonSet.

---

## 10. Jupyter notebooks for a Kubernetes security lab — precedent and recommended setup

**Is there good precedent? Yes.**
- **DFIR/threat-hunting in Jupyter is well established.** Microsoft's **MSTICpy** (msticpy.readthedocs.io) is a mature InfoSec-in-Jupyter library: pandas-centric, data connectors (Splunk, Sentinel, M365D, Sumo), threat-intel enrichment, IoC extraction — and it lists **OTRF (Open Threat Research)** datasets as a provider. The **OTRF Threat Hunter Playbook** / Security Datasets project popularized notebook-driven detection over structured log data.
- **Kubernetes + Python in notebooks** is natural via the official **`kubernetes` Python client** (list/watch resources, read RBAC, drive scenarios). **KubeHound ships Jupyter support** for querying its attack-path graph (Gremlin), i.e. a real precedent for notebook-driven k8s attack analysis.
- **Audit-log analysis with pandas** is a strong fit: load the JSON audit log, normalize with `pandas.json_normalize`, group by `user.username`/`verb`/`objectRef`, and flag anomalies (e.g. `pods/exec`, token creation, anonymous requests, missing-audit `nodes/proxy` gaps). This pairs directly with your audit-logging component.

**Recommended current setup (2026):**
- **JupyterLab 4.x** (latest stable **4.6.4**, 2026-09; no 5.0 line yet) as the environment.
- **`uv`** for fast, reproducible Python envs: `uv venv && uv pip install jupyterlab kubernetes pandas msticpy` (plus `picklescan`/`modelscan` for the AI module). `uv` is the current best practice over raw pip/venv.
- **`bash_kernel`** (`pip install bash_kernel && python -m bash_kernel.install`) so attack/defense cells can run `kubectl`, `kubeletctl`, `cosign`, `trivy`, `kube-bench` directly as Bash — ideal for an attack/defense lab where commands *are* the lesson. Maintenance is low-frequency but it works on Jupyter 4.x; pin it.
- Alternatively **VS Code notebooks** (`.ipynb`) if learners already use VS Code — same kernels, better git diffs, integrated terminal. Good for authoring; JupyterLab is better for a self-contained hosted lab.
- Structure: one notebook per scenario with **Attack** (bash_kernel cells), **Observe** (pandas over audit log / Falco alerts via falcosidekick webhook → file → pandas), and **Defend** (apply Kyverno/VAP policy, re-run, show the block). This mirrors the detect→respond loop and keeps everything reproducible.
- Keep notebooks and any downloaded attack tooling in **separate directories**, and run cluster workloads in the k3d cluster, not on the notebook host.

---

## Exercise ideas

See `docs/LAB_MODERNIZATION_PROPOSAL.md`, which turns this brief into the module plan.

### Items flagged UNVERIFIED / needing a primary-source check before you rely on them
- OWASP Kubernetes Top 10 2025 exact publication date.
- BuildKit Leaky Vessels fixed version (0.12.5, from memory).
- NVIDIA CVE-2024-0132 exact fixed versions (1.16.2 / 24.6.2).
- Helm 4 GA status/date.
- KMS v2 having any change after its v1.29 GA (treated as unchanged).
- vLLM CVE-2026-22778; Langflow KEV CVE numbers/dates; TeamPCP wiper specifics; Falco Talon current version — all rest on secondary/vendor sources.
- CIS Kubernetes Benchmark v2.0.1 ↔ kube-bench profile mapping (kube-bench only confirmed through cis-1.12).
- NIST SP 800-190 Rev 1 existence (none found).
- rakkess current status (not re-checked).
