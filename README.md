# Secure Software Supply Chain & SBOM Pipeline

GitHub Actions pipeline that builds a container image with BuildKit, generates an SBOM (Syft),
scans dependencies and the image (Trivy), signs and attests (Cosign, keyless), produces SLSA
Level 3 provenance, publishes to GHCR, and **blocks the release when policy thresholds are breached**.

## Flow

```
push ──► build (BuildKit) ──► push :<sha> ──► Syft SBOM ──► Trivy scan (image + fs)
                                                   │
                                                   ▼
                                          policy_gate.py ──fail──► pipeline stops, nothing signed
                                                   │pass
                                                   ▼
                                  cosign sign + attest SBOM (by digest)
                                                   ▼
                            SLSA generator (isolated reusable workflow) ──► provenance
                                                   ▼
                          release: verify signature ► retag :latest (same digest)
```

## Layout

| Path | Purpose |
|---|---|
| `app/`, `requirements.txt`, `Dockerfile` | Sample Flask service, multi-stage, non-root |
| `.github/workflows/supply-chain.yml` | The pipeline |
| `policy/policy.json` | Thresholds, denied licenses, expiring waivers |
| `scripts/policy_gate.py` | Gate: reads Trivy JSON + CycloneDX SBOM, exits 1 on breach |
| `scripts/verify.sh` | Consumer-side verification of signature, SBOM attestation, provenance |
| `tests/` | Unit tests for the gate with fixtures |

## Policy (default)

- 0 CRITICAL, at most 3 HIGH (fixable only; `ignore_unfixed: true`)
- SBOM must exist with a minimum component count
- Denied licenses: AGPL, SSPL
- Waivers need an ID, reason and **expiry date**; expired waivers stop applying automatically

## Setup

1. Push this repo to GitHub; replace `OWNER/REPO` in the `Dockerfile` label.
2. Settings → Actions → Workflow permissions: allow read/write (needed for GHCR) .
3. Push to `main`. No secrets needed: Cosign uses GitHub OIDC (keyless), GHCR uses `GITHUB_TOKEN`.
4. Make the package public, or pull with a token, to run verification.

## Run the gate locally

```bash
pip install pytest
pytest -q
trivy image --format json -o trivy.json IMAGE
syft IMAGE -o cyclonedx-json=sbom.cdx.json
python scripts/policy_gate.py --trivy trivy.json --sbom sbom.cdx.json --policy policy/policy.json
```

## Verify a release

```bash
scripts/verify.sh ghcr.io/OWNER/REPO@sha256:<digest> OWNER/REPO
```

Needs `cosign` and `slsa-verifier` installed.

## Demo for evaluation

1. **Pass path:** push as-is; show the green run, signature and attestations in GHCR, `verify.sh` output.
2. **Block path:** change `requirements.txt` to an old vulnerable version (e.g. `flask==0.12`) and push a branch to `main` via PR merge; the gate fails, nothing is signed or promoted. Screenshot the step summary.
3. **Tamper check:** `cosign verify` on an image pushed manually without signing fails.

## Design notes

- Signing happens **after** the gate and **by digest**, never by mutable tag.
- Trivy runs with `exit-code: 0`; the gate is the single decision point, so policy is versioned, testable and auditable.
- Provenance uses the isolated SLSA generator so the build job cannot forge it (this is what yields SLSA L3).
- Pin third-party actions to commit SHAs for production use (tags shown for readability).
