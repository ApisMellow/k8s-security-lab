#!/usr/bin/env bash
set -euo pipefail
IMAGE="${1:-nginx:latest}"
EXTRA_ARGS="${TRIVY_ARGS:-}"
echo "==> Trivy image scan: $IMAGE"
echo "    Severity: HIGH,CRITICAL | Exit nonzero on findings"
trivy image --skip-version-check --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed ${EXTRA_ARGS} "$IMAGE"
