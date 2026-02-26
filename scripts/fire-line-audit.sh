#!/usr/bin/env bash
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
#
# fire-line-audit.sh — scan the codebase for forbidden identifiers.
# Exit 1 if any violation is found.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Forbidden identifiers per FIRE_LINE.md
FORBIDDEN=(
  "TrustAttestation"
  "TrustBundle"
  "BehavioralBiometric"
  "SocialIdentity"
  "LegalIdentity"
  "HumanAgentBinding"
  "progressLevel"
  "promoteLevel"
  "computeTrustScore"
  "behavioralScore"
  "adaptiveBudget"
  "optimizeBudget"
  "predictSpending"
  "detectAnomaly"
  "generateCounterfactual"
  "PersonalWorldModel"
  "MissionAlignment"
  "SocialTrust"
  "CognitiveLoop"
  "AttentionFilter"
  "GOVERNANCE_PIPELINE"
)

VIOLATIONS=0

for TERM in "${FORBIDDEN[@]}"; do
  # Search source files only (skip this script, FIRE_LINE.md, and CLAUDE.md)
  MATCHES=$(grep -rn --include="*.go" --include="*.ts" --include="*.py" \
    "${TERM}" "${ROOT_DIR}" \
    --exclude-dir=node_modules \
    --exclude-dir=vendor \
    --exclude-dir=.git \
    2>/dev/null || true)

  if [[ -n "${MATCHES}" ]]; then
    echo "FIRE LINE VIOLATION — forbidden identifier: ${TERM}"
    echo "${MATCHES}"
    echo ""
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

if [[ "${VIOLATIONS}" -gt 0 ]]; then
  echo "fire-line-audit: ${VIOLATIONS} violation(s) found. Aborting."
  exit 1
fi

echo "fire-line-audit: no violations found."
