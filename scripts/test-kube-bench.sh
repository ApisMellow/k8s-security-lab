#!/usr/bin/env bash
# Simple MVP to test kube-bench execution and display results

set -euo pipefail

REPORT_DIR="/tmp/kube-bench-test"
mkdir -p "$REPORT_DIR"

echo "==> Creating exempted namespace..."
kubectl create namespace phase5-test --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null

echo "==> Running kube-bench pod..."
kubectl run kube-bench \
  --image=aquasec/kube-bench:latest \
  --restart=Never \
  -n phase5-test \
  -- run --json 2>&1 | tee "${REPORT_DIR}/pod-creation.log" &

POD_PID=$!

echo "==> Waiting for pod to complete..."
sleep 3

# Wait for pod to be done (either Completed or Failed)
kubectl wait --for=condition=Ready pod/kube-bench -n phase5-test --timeout=120s 2>/dev/null || true

echo "==> Getting pod logs..."
sleep 2
kubectl logs kube-bench -n phase5-test > "${REPORT_DIR}/kube-bench-results.json" 2>&1

echo "==> Pod output saved to: ${REPORT_DIR}/kube-bench-results.json"
echo ""

# Check if we got valid JSON
if [ -s "${REPORT_DIR}/kube-bench-results.json" ]; then
  echo "==> File size: $(wc -c < ${REPORT_DIR}/kube-bench-results.json) bytes"
  echo ""
  echo "==> First 200 chars:"
  head -c 200 "${REPORT_DIR}/kube-bench-results.json"
  echo ""
  echo ""

  # Try to parse JSON
  if jq empty "${REPORT_DIR}/kube-bench-results.json" 2>/dev/null; then
    echo "✅ Valid JSON"
    echo ""
    echo "==> Summary by Control Group:"
    jq -r '.Controls[] | "[\(.id)] \(.text)"' "${REPORT_DIR}/kube-bench-results.json"

    echo ""
    echo "==> Sample Failed Checks (first 15):"
    jq -r '.Controls[] | .tests[] | .results[] | select(.status=="FAIL") | "\(.test_number): \(.test_desc)"' "${REPORT_DIR}/kube-bench-results.json" | head -15

    echo ""
    echo "==> Total Failed Checks:"
    jq '[.Controls[] | .tests[] | .results[] | select(.status=="FAIL")] | length' "${REPORT_DIR}/kube-bench-results.json"
  else
    echo "❌ Invalid JSON or parsing error"
    head -20 "${REPORT_DIR}/kube-bench-results.json"
  fi
else
  echo "❌ No output captured"
fi

echo ""
echo "==> Cleaning up..."
kubectl delete namespace phase5-test --ignore-not-found=true 2>/dev/null

echo "Done"
