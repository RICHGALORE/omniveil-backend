# Omni Veil Backend Deployment

The production API is designed for Render with Render PostgreSQL. `render.yaml` is the canonical infrastructure contract for the service, database, persistent disk, health check, and non-secret environment settings.

## Render Blueprint contract

The checked-in `render.yaml` declares:

- Docker web service `omniveil-backend` on paid `0.5c-512mb` compute;
- `autoDeployTrigger: checksPass` so GitHub CI must pass before automatic deployment;
- platform health check at `/health`;
- a 10 GB persistent disk mounted at `/app/uploads`;
- paid `omniveil-db` Postgres on `0.1c-256mb` compute;
- `DATABASE_URL` linked from that database;
- `ENVIRONMENT=production`, `UPLOAD_DIR=/app/uploads`, and production demo seeding disabled;
- tenant-scoped rate-limit defaults for Upload, OmniSpectra, and C2PA;
- secret-only variables declared with `sync: false` so their values are never committed.

Render preserves existing resources with matching names when a Blueprint is synced. Treat a Blueprint sync as an infrastructure change: review the Render diff before applying it. Persistent disks require a paid Render web service.

## Required production secrets

These values must be stored in Render's secret/environment configuration and must never be committed:

- `OV_SIGNING_SECRET` — a new production-only random secret
- `ADMIN_API_KEY` — a new production-only random admin key
- `OV_SIGNING_PRIVATE_KEY_B64` — production Ed25519 Trust Authority private key
- `OV_SIGNING_PUBLIC_KEY_B64` — matching production Ed25519 public key
- `OV_SIGNING_KEY_ID` — stable production key identifier, for example `OV-ROOT-PROD-001`
- `ALLOWED_ORIGINS` — canonical production Vercel origin(s), comma-separated, without trailing slashes
- `SIGHTENGINE_USER` / `SIGHTENGINE_SECRET` when synthetic-media detection is enabled

If the existing Render service is already managed by a Blueprint, adding a new `sync: false` variable does not populate its value automatically. Set missing secret values manually in Render before expecting `/ready` to pass.

The service validates that the configured Ed25519 public key belongs to the configured private key and refuses to issue certificates in production if signing configuration is missing, invalid, or mismatched. It never falls back to the local development root when `ENVIRONMENT=production`.

If production demo seeding is deliberately enabled, set `DEMO_API_KEY` explicitly. The service will not generate or log a production demo credential.

## Container contract

Build from the repository `Dockerfile`. The container:

- runs Python 3.11 as an unprivileged user;
- installs ExifTool for metadata extraction;
- uses `/app` as its working directory;
- pins `UPLOAD_DIR=/app/uploads` so application and Render disk paths agree;
- listens on Render's `PORT` value;
- exposes `/health` for process liveness;
- exposes `/ready` for dependency readiness.

`/health` deliberately stays lightweight so infrastructure can tell whether the API process is alive even during a database/configuration incident. `/ready` is the stricter gate and checks database connectivity, writable persistent upload storage, and production Trust Authority signing configuration. It returns HTTP `503` when any required dependency is unavailable and exposes only public-safe booleans, never credentials or secret details.

## Persistent storage

Uploaded originals, watermarked files, certificates, and manifests are written under `/app/uploads`. The Render disk must be mounted at that exact path before accepting production uploads. Only files under the disk mount survive deploys and restarts.

The storage helper also understands legacy database paths such as `uploads/originals/...`, so existing records remain resolvable after the persistent root becomes explicit.

## Release check

After deployment, verify liveness first:

```bash
curl https://omniveil-backend.onrender.com/health
```

Expected response:

```json
{"status":"ok","version":"0.1.0","env":"production"}
```

Then verify the service is actually ready to accept Trust OS work:

```bash
curl -i https://omniveil-backend.onrender.com/ready
```

Expected production response after Postgres, persistent storage, and signing secrets are configured:

```json
{
  "status": "ready",
  "ready": true,
  "environment": "production",
  "checks": {
    "database": true,
    "storage": true,
    "trust_signing": true
  }
}
```

Before accepting uploads, issue one controlled certificate and verify that its `public_key_id` is the configured production key ID, never `OV-ROOT-DEV-001`.
