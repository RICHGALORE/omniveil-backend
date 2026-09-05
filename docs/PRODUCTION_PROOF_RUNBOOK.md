# Omni Veil Production Proof Runbook

This runbook turns production readiness into repeatable evidence instead of a manual checklist.

The core proof runner creates a deliberately non-commercial smoke-test asset and validates the live Trust OS path without storing or printing the tenant API key. A second forensic proof runner validates configured external detector providers without collapsing their probabilities into an authenticity score.

## What a passing core create run proves

A successful `scripts/production_proof.py` create run verifies all of the following against the live deployment:

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

## Prove core persistence after a restart or deploy

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

## Prove live external forensic providers

External detectors are optional dependencies, so they deliberately do not control `/ready`. Prove them separately with `scripts/production_forensic_proof.py` after the core production proof is green.

The runner defaults to expecting both Sightengine and Hive:

```bash
export OV_API_KEY='YOUR_TENANT_API_KEY'
export OV_EXPECTED_DETECTOR_PROVIDERS='sightengine,hive'
python scripts/production_forensic_proof.py \
  --omni-id 'OV-...' \
  --report production-forensic-proof-create.json
```

A passing refresh run proves:

1. The registered original is still available to the backend.
2. The external detector refresh endpoint returns at least one observation.
3. Every expected provider is present in OmniSpectra.
4. Every expected provider has its own model/signal/probability row.
5. Probabilities remain provider-specific and `consensus_score` remains `null`.
6. The refresh did not rewrite registration facts.
7. The refresh did not rewrite the historical Trust Score.
8. The provider observations were persisted.
9. Evidence Graph contains forensic-observation nodes for every expected provider.

For image/video proof assets, configure Sightengine plus `HIVE_MEDIA_API_KEY`. For a Heavy Handed Productions audio flagship, configure Sightengine plus the appropriate Hive audio/music project key (`HIVE_AUDIO_API_KEY` and/or `HIVE_MUSIC_API_KEY`).

A provider failure is a failed forensic proof, but it does not make the core Trust OS `/ready` check fail. That separation prevents a third-party detector outage from taking the platform offline.

## Prove forensic persistence without another vendor call

After a restart/deploy, run the same Omni ID with `--no-refresh`:

```bash
python scripts/production_forensic_proof.py \
  --omni-id 'OV-...' \
  --no-refresh \
  --report production-forensic-proof-recheck.json
```

This reads the already-persisted provider observations and requires them to remain visible in both OmniSpectra and Evidence Graph. A passing recheck proves the forensic evidence rows survived in Postgres without spending another external-provider request.

## Recommended production activation order

Use this order for the canonical production environment:

1. Bring Render Postgres and the backend service online.
2. Configure the persistent disk and production Ed25519 signing secrets.
3. Confirm `/health` and `/ready` are green.
4. Run the core create proof.
5. Restart/redeploy Render and run the core persistence recheck.
6. Configure Sightengine and the appropriate Hive project keys.
7. Run the external forensic-provider refresh proof.
8. Restart/redeploy and run the forensic `--no-refresh` persistence proof.
9. Only then run the first real Heavy Handed Productions HumanProof flagship through the same live environment.

That order separates infrastructure proof, third-party forensic proof, and real creator evidence so a failure has a clear cause.

## Failure semantics

Both runners exit non-zero on failed proof conditions. They fail closed rather than downgrading required conditions to warnings.

Examples of conditions that fail the core run:

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

Examples of conditions that fail the forensic run:

- the registered source file is unavailable;
- no configured detector returns an observation;
- Sightengine or Hive is expected but absent;
- a provider probability is outside `0..1` or not marked available;
- OmniSpectra reports a non-null consensus score;
- a detector refresh claims it rewrote registration or Trust Score state;
- Evidence Graph loses one of the expected provider nodes after persistence.

## Security boundary

Prefer environment variables over `--api-key` so credentials do not appear in shell history.

The proof reports never include the tenant API key, signing private key, database URL, admin key, raw provider API keys, raw provider payloads, or raw HumanProof private evidence.

Neither proof is a legal determination of authenticity, authorship, originality, copyright ownership, or fraud. External detector probabilities remain independent forensic observations only.
