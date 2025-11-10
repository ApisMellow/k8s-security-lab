#!/usr/bin/env bash
# Phase 1: Basic cluster creation (no audit logging)
#
# This is the MANUAL PATH for Phase 1. Use this if you want to understand each step.
# For the automated path, use the Makefile: make phase1
#
# This creates a basic k3d cluster without audit logging.
# After learning with this, upgrade to cluster-up-phase1-with-audit.sh to enable audit logging.
#
# Usage:
#   ./scripts/cluster-up-phase1-basic.sh              # creates cluster named 'dev'
#   ./scripts/cluster-up-phase1-basic.sh myenv        # creates cluster named 'myenv'

set -euo pipefail
NAME="${1:-dev}"
echo "[+] Creating k3d cluster '$NAME' (basic, no audit logging)..."
k3d cluster create "$NAME" --agents 2
echo "[+] kubeconfig set. Verifying..."
kubectl cluster-info
kubectl get nodes -o wide
echo ""
echo "Next step: Enable audit logging with:"
echo "  ./scripts/cluster-down.sh"
echo "  ./scripts/cluster-up-phase1-with-audit.sh"
