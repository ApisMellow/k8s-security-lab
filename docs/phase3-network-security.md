# Kubernetes Security Lab – Phase 3: Network Segmentation & Egress Controls

**Goal:** Enforce namespace isolation by default, allow only the minimum ingress/egress needed (DNS, intra-app), and add simple tests. This phase assumes a CNI that **enforces** NetworkPolicy (e.g., Cilium or Calico). If policies don’t have effect, install a policy-aware CNI first.  
See Phase plan: “Install Calico/Cilium; create NetworkPolicies for isolation.” (Lab Workbook)  
See project roadmap: “Phase 3 — Network segmentation, namespace isolation, egress controls, and secrets management.” (Context Summary)

