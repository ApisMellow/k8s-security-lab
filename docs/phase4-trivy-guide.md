# Phase 4 — Trivy Scanning Guide

## Install via Devbox/Nix
```
devbox add trivy
devbox run trivy version
```
Or add `trivy` to the `packages` in devbox.json and run `devbox install`.

## Usage

Trivy is automatically available in devbox shell. Run scans with:

**Image Scanning:**
```bash
bash scanners/trivy-scan-image.sh nginx:latest
```

**Cluster Scanning:**
```bash
bash scanners/trivy-scan-cluster.sh
```

**Manifest Scanning:**
```bash
bash scanners/trivy-scan-manifests.sh policies/
bash scanners/trivy-scan-manifests.sh network-policies/
```

**Via Makefile (after phase4-harden succeeds):**
```bash
make phase4-scan
```

**Save scan report to disk:**
```bash
make phase4-scan > phase4-scan-$(date +%Y%m%d-%H%M%S).txt 2>&1
```
