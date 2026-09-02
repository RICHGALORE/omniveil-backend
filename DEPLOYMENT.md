# Omni Veil Backend Deployment

The production API is designed for Render with Render PostgreSQL.

## Required environment

- `ENVIRONMENT=production`
- `DATABASE_URL` set to the Render PostgreSQL connection string
- `OV_SIGNING_SECRET` set to a new production-only random secret
- `ADMIN_API_KEY` set to a new production-only random key
- `OV_SIGNING_PRIVATE_KEY_B64` set to the production Ed25519 Trust Authority private key
- `OV_SIGNING_PUBLIC_KEY_B64` set to the matching production Ed25519 public key
- `OV_SIGNING_KEY_ID` set to the stable production key identifier (for example `OV-ROOT-PROD-001`)
- `ALLOWED_ORIGINS` set to the production Vercel origin, without a trailing slash
- `SEED_DEMO_CLIENT=false` unless a deliberate production demo tenant is required

The Ed25519 keypair must be generated and stored outside Git. Render secret configuration is acceptable for the first production boundary; KMS / a dedicated secrets manager is the next hardening step. The service validates that the configured public key belongs to the configured private key and refuses to issue certificates in production if the signing configuration is missing, invalid, or mismatched. It never falls back to the local development root when `ENVIRONMENT=production`.

If production demo seeding is deliberately enabled, set `DEMO_API_KEY` explicitly.
The service will not generate or log a production demo credential.

## Container contract

Build from the repository `Dockerfile`. The container:

- runs Python 3.11 as an unprivileged user;
- installs ExifTool for metadata extraction;
- listens on Render's `PORT` value;
- exposes `/health` as its container health check.

## Persistent storage

Uploaded originals, watermarked files, certificates, and manifests are written under
`/app/uploads`. Attach a persistent Render disk at that path before accepting production
uploads. Certificate verification can recover from the database, but generated media files
still require durable storage.

## Release check

After deployment:

```bash
curl https://omniveil-backend.onrender.com/health
```

Expected response:

```json
{"status":"ok","version":"0.1.0","env":"production"}
```

Before accepting uploads, issue one controlled certificate and verify that its `public_key_id` is the configured production key ID, never `OV-ROOT-DEV-001`.
