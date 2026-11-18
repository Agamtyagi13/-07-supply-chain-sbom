#!/usr/bin/env bash
# Verify a released image: signature, SBOM attestation, SLSA provenance.
# Usage: scripts/verify.sh ghcr.io/OWNER/REPO@sha256:<digest> OWNER/REPO
set -euo pipefail
IMAGE="${1:?image@digest required}"
REPO="${2:?owner/repo required}"
ISSUER="https://token.actions.githubusercontent.com"
IDENTITY_RE="^https://github.com/${REPO}/\.github/workflows/.+@refs/(heads/main|tags/v.+)$"

echo "== cosign signature =="
cosign verify "$IMAGE" \
  --certificate-oidc-issuer "$ISSUER" \
  --certificate-identity-regexp "$IDENTITY_RE" >/dev/null && echo OK

echo "== CycloneDX SBOM attestation =="
cosign verify-attestation "$IMAGE" --type cyclonedx \
  --certificate-oidc-issuer "$ISSUER" \
  --certificate-identity-regexp "$IDENTITY_RE" >/dev/null && echo OK

echo "== SLSA provenance =="
slsa-verifier verify-image "$IMAGE" \
  --source-uri "github.com/${REPO}" --source-branch main && echo OK
