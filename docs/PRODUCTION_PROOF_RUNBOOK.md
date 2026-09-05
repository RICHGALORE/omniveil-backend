# Omni Veil Production Proof Runbook

This runbook turns production readiness into repeatable evidence instead of a manual checklist.

The proof runner creates a deliberately non-commercial smoke-test asset and validates the live Trust OS path without storing or printing the tenant API key.

## What a passing create run proves

A successful create run verifies all of the following against the live deployment:

1. `/health` responds and the service reports the production environment.
2. `/ready` reports `database`, `storage`, and `trust_signing` as ready.
3. Authenticated ingest accepts a fresh file and returns a new Omni ID and certificate ID.
4. The watermark write path is exercised.
5. A HumanProof session records creation-process evidence, an explicit AI-use disclosure, asset binding, closure, and a valid hash chain.
6. The issued certificate verifies with Ed25519.
7. The certificate does not use `OV-ROOT-DEV-001`.
8. If `OV_EXPECTED_SIGNING_KEY_ID` is supplied, the observed production key ID must match it exactly.
9. Public Verify exposes the bound HumanProof summary.
10. Public Registry exposes the same bound HumanProof summary.
11. The tenant-scoped Evidence Graph contains certificate and creation-process evidence.
12. Fact Integrity returns `consistent` with zero mismatches.

This is an infrastructure/product-path proof. The generated PNG is not presented as a commercial artwork, copyright registration, originality determination, or legal authorship ruling.

## Create a proof asset

From the backend repository with dependencies installed:

```bash
export OV_API_KEY='YOUR_TENANT_API_KEY'
export OV_EXPECTED_SIGNING_KEY_ID='OV-ROOT-PROD-001'
python scripts/production_proof.py --report production-proof-create.json
```

The script defaults to:

```text
https://omniveil-backend.onrender.com
```

Override it when validating another canonical deployment:

```bash
export OV_BASE_URL='https://your-production-api.example.com'
```

A passing run prints only non-secret identifiers and writes a secret-free JSON report containing the Omni ID, certificate ID, HumanProof session ID, production public key ID, readiness state, Fact Integrity state, and Evidence Graph version.

Do not commit the generated proof report if it contains identifiers you do not want in source control.

## Prove persistence after a restart or deploy

The create run proves that the live stack can write and read the Trust OS records. Persistent storage is proven only after the same records survive a service restart or deployment.

After the Render service has restarted or a new deployment is live, use the Omni ID and certificate ID from the create report:

```bash
export OV_API_KEY='YOUR_TENANT_API_KEY'
export OV_EXPECTED_SIGNING_KEY_ID='OV-ROOT-PROD-001'
python scripts/production_proof.py \
  --recheck-omni-id 'OV-...' \
  --expected-cert-id '...' \
  --report production-proof-recheck.json
```

The recheck requires:

- the original asset to remain publicly verifiable;
- the original HumanProof record to remain complete and asset-bound;
- the original certificate ID to remain available when `--expected-cert-id` is provided;
- the certificate signature to remain valid under the expected production key;
- Registry to remain readable;
- Evidence Graph to remain available;
- Fact Integrity to remain `consistent` after the new Verify event is logged.

A passing recheck is the evidence that the canonical database + persistent disk + Trust Authority path survived the restart/deploy.

## Failure semantics

The runner exits non-zero on any failed proof condition. It fails closed rather than downgrading failures to warnings.

Examples of conditions that fail the run:

- production readiness is `503` or any required readiness check is false;
- the environment is not `production`;
- the smoke upload reuses an existing registration unexpectedly;
- HumanProof is incomplete, unbound, or its event chain is invalid;
- the certificate signature is invalid;
- the production certificate uses `OV-ROOT-DEV-001`;
- the configured expected key ID does not match the observed key;
- public Verify or Registry loses the HumanProof summary;
- Evidence Graph loses required certificate or creation-process evidence;
- Fact Integrity reports `review_required` or `incomplete` instead of `consistent`.

## Security boundary

Prefer environment variables over `--api-key` so credentials do not appear in shell history.

The proof report never includes the tenant API key, signing private key, database URL, admin key, or raw HumanProof private evidence.
