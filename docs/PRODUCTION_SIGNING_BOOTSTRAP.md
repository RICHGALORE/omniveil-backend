# Production Trust Authority Signing Bootstrap

Omni Veil production certificates use an Ed25519 Trust Authority root. Production deliberately fails closed when the root is missing, invalid, mismatched, or still using the development key identity.

## Generate the root locally

From the backend repository root:

```bash
python scripts/generate_production_signing_keys.py
```

The command writes:

```text
.secrets/ov_root_prod_keypair.json
```

The `.secrets/` directory is gitignored. On POSIX systems the file is created with mode `0600`.

The command prints only:

- the local secret-file path;
- the production key ID;
- the SHA-256 fingerprint of the public key.

It **never prints the private key**.

The JSON file contains the exact three names required by production:

- `OV_SIGNING_PRIVATE_KEY_B64`
- `OV_SIGNING_PUBLIC_KEY_B64`
- `OV_SIGNING_KEY_ID`

Transfer those values directly into Render's secret/environment configuration. Do not paste them into source code, issues, pull requests, CI logs, chat, screenshots, or public documentation.

## Stable key ID

By default the generator derives a stable key ID from the public-key fingerprint:

```text
OV-ROOT-PROD-<12 hex characters>
```

To use an explicit organizational identifier instead:

```bash
python scripts/generate_production_signing_keys.py --key-id OV-ROOT-PROD-001
```

The development identity `OV-ROOT-DEV-001` is rejected.

## Rotation is explicit

The generator refuses to overwrite an existing local root. That prevents an accidental command rerun from silently changing the Trust Authority.

An intentional rotation requires `--force`:

```bash
python scripts/generate_production_signing_keys.py --force
```

Treat rotation as a production security event. Existing certificates remain verifiable with the public key embedded in their certificate, but operational systems and expected key-ID checks must be updated deliberately.

## Verify production readiness

After the three values are installed in Render and the service has redeployed:

```bash
curl -i https://omniveil-backend.onrender.com/ready
```

The signing portion must report:

```json
{
  "trust_signing": true
}
```

The full readiness endpoint is green only when database, storage, and trust signing are all true.

Then run the executable production proof with the expected production key ID:

```bash
export OV_API_KEY='YOUR_TENANT_API_KEY'
export OV_EXPECTED_SIGNING_KEY_ID='OV-ROOT-PROD-001'
python scripts/production_proof.py --report production-proof-create.json
```

Never place the private signing key in `OV_EXPECTED_SIGNING_KEY_ID` or any command-line argument.

## Backup

The production private key is a Trust Authority credential. Keep at least one encrypted offline backup under founder/company control before deleting the local bootstrap file. Losing the root does not invalidate already-issued signatures, but it prevents Omni Veil from issuing new certificates under the same key identity.
