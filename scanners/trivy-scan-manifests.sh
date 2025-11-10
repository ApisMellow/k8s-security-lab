#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-.}"
EXTRA_ARGS="${TRIVY_ARGS:-}"
echo "==> Trivy config scan in: $TARGET"
trivy config --skip-version-check ${EXTRA_ARGS} "$TARGET"
