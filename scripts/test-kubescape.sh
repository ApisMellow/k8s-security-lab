#!/usr/bin/env bash
# Simple MVP to test kubescape execution and display results

set -euo pipefail

REPORT_DIR="/tmp/kubescape-test"
mkdir -p "$REPORT_DIR"

echo "==> Running kubescape scan..."
kubescape scan framework NSA,cis-v1.10.0 \
  --format json \
  --output "${REPORT_DIR}/kubescape-results.json" \
  2>&1 | tee "${REPORT_DIR}/kubescape.log"

echo ""
echo "==> Kubescape output saved to: ${REPORT_DIR}/kubescape-results.json"
echo ""

# Check if we got valid JSON
if [ -s "${REPORT_DIR}/kubescape-results.json" ]; then
  echo "==> File size: $(wc -c < ${REPORT_DIR}/kubescape-results.json) bytes"
  echo ""

  # Try to parse JSON
  if jq empty "${REPORT_DIR}/kubescape-results.json" 2>/dev/null; then
    echo "✅ Valid JSON"
    echo ""
    echo "==> Summary:"

    # Extract overall score
    SCORE=$(jq '.summaryDetails.complianceScore // 0' "${REPORT_DIR}/kubescape-results.json" | xargs printf "%.0f")
    echo "Overall Compliance Score: ${SCORE}%"
    echo ""

    # Count control statuses
    PASSED=$(jq '[.summaryDetails.controls[]? | select(.status=="passed")] | length' "${REPORT_DIR}/kubescape-results.json")
    FAILED=$(jq '[.summaryDetails.controls[]? | select(.status=="failed")] | length' "${REPORT_DIR}/kubescape-results.json")
    SKIPPED=$(jq '[.summaryDetails.controls[]? | select(.status=="skipped")] | length' "${REPORT_DIR}/kubescape-results.json")

    echo "Control Status:"
    echo "  ✅ Passed: ${PASSED}"
    echo "  ❌ Failed: ${FAILED}"
    echo "  ⏭️  Skipped: ${SKIPPED}"
    echo ""

    if [ "${FAILED}" -gt 0 ]; then
      echo "==> Sample Failed Controls (first 15):"
      jq -r '.summaryDetails.controls[]? | select(.status=="failed") | "  [\(.controlID)] \(.name)"' "${REPORT_DIR}/kubescape-results.json" | head -15
      echo ""
    fi

    # Show failed resources if available
    FAILED_RESOURCES=$(jq '[.summaryDetails.controls[]? | select(.status=="failed") | .resourceIDs[]?] | length' "${REPORT_DIR}/kubescape-results.json" 2>/dev/null || echo 0)
    if [ "${FAILED_RESOURCES}" -gt 0 ]; then
      echo "Failed Resources: ${FAILED_RESOURCES}"
    fi
  else
    echo "❌ Invalid JSON"
    head -20 "${REPORT_DIR}/kubescape-results.json"
  fi
else
  echo "❌ No output captured"
  cat "${REPORT_DIR}/kubescape.log"
fi

echo ""
echo "Done"
