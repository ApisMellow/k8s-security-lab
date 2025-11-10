#!/usr/bin/env bash
set -euo pipefail
EXTRA_ARGS="${TRIVY_ARGS:-}"
echo "==> Trivy cluster scan (current kube-context)"
trivy k8s --skip-version-check --report summary --severity HIGH,CRITICAL ${EXTRA_ARGS}
