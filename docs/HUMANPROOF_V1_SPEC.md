# Omni Veil HumanProof V1

HumanProof is an evidence-backed creation provenance layer. It does not claim to prove that a human created a work from a single classifier result. It records, hashes, chains, and verifies evidence about how a work was created.

## V1 objective

Demonstrate one complete creation workflow:

`creation session -> evidence events -> asset fingerprint -> registration -> certificate -> public verification`

HumanProof complements OmniSpectra forensic analysis and OmniRisk. Forensic signals may support or challenge a provenance claim, but they do not silently rewrite the creator's declared history.

## Evidence event

Every HumanProof event must contain:

- `event_id`: immutable unique identifier
- `omni_id`: registered asset identifier when available
- `session_id`: HumanProof creation-session identifier
- `event_type`: controlled event type
- `occurred_at`: UTC timestamp supplied by the capture workflow
- `recorded_at`: UTC timestamp recorded by Omni Veil
- `evidence_hash`: SHA-256 of canonical event evidence
- `previous_event_hash`: hash link to the previous event in the session, or null for genesis
- `source_type`: capture source such as web, DAW, mobile, import, or API
- `source_name`: optional application/device/workflow name
- `creator_id`: tenant-scoped creator identifier when authenticated
- `ai_disclosure`: structured disclosure of AI participation when relevant
- `location`: optional privacy-aware location evidence
- `payload`: versioned structured evidence payload
- `schema_version`: HumanProof event schema version

## V1 event types

- `session_started`
- `source_captured`
- `work_saved`
- `work_exported`
- `ai_tool_disclosed`
- `contributor_attested`
- `asset_registered`
- `session_closed`

Additional event types require a schema-version update or backwards-compatible registry addition.

## Location privacy

HumanProof must never require exact GPS for a valid human-provenance record.

Location evidence supports three levels:

1. `none` — no location captured.
2. `coarse` — city/region or deliberately reduced precision.
3. `precise_private` — precise coordinates encrypted/private and excluded from public verification.

Public certificates expose only a safe location summary explicitly approved for publication.

## AI disclosure

AI participation is provenance, not automatic fraud. V1 records:

- whether AI was used;
- declared tools;
- declared role (`generation`, `assist`, `edit`, `master`, `stem`, `other`);
- creator statement/attestation;
- disclosure timestamp.

OmniSpectra may independently produce synthetic-media or workflow-lineage signals. The declaration and forensic result remain separate evidence sources.

## Chain integrity

Events are canonicalized before hashing. Each event links to the prior event hash. Verification must detect:

- missing events;
- reordered events;
- changed payloads;
- broken previous-hash links;
- an evidence hash that no longer matches canonical event data.

A valid chain proves integrity of the recorded HumanProof history after capture. It does not by itself prove every real-world claim in the history is true.

## Public vs private evidence

Public verification may expose:

- HumanProof status;
- creation/session date range;
- evidence event count;
- chain-integrity status;
- AI disclosure summary;
- contributor attestations intended for publication;
- coarse approved location summary;
- certificate and asset fingerprint references.

Private evidence includes precise location, raw device identifiers, private metadata, internal forensic details, API credentials, and sensitive creator information.

## HumanProof status

V1 statuses:

- `not_started`
- `recording`
- `complete`
- `integrity_failed`
- `incomplete`

`complete` means the required evidence sequence exists and its cryptographic chain verifies. It must not be presented as a universal guarantee that a human performed every creative act.

## Required V1 completion sequence

A session is eligible for `complete` when it contains at minimum:

1. `session_started`
2. at least one `source_captured`, `work_saved`, or `work_exported` event
3. an AI disclosure state, including an explicit declaration of no AI use when applicable
4. `asset_registered` tied to the final asset fingerprint
5. `session_closed`
6. a valid evidence-hash chain

## Integration points

### Upload / Registry
The final HumanProof session links to the registered Omni ID and immutable asset fingerprint.

### OmniSpectra
Forensic and workflow-lineage results are independent evidence attached to the asset. They can corroborate or conflict with HumanProof claims.

### OmniRisk
HumanProof chain integrity becomes one explainable OmniRisk signal. It must not dominate the score by itself.

### Live-Split
Contributor attestations and percentages may reference the HumanProof session so authorship/rights claims can be connected to creation evidence.

### Certificate / Verify
Certificates may state that HumanProof evidence exists and whether its chain verifies. Sensitive evidence remains private.

## Non-goals for V1

- claiming perfect human-vs-AI detection;
- exposing precise private location publicly;
- silently editing timestamps or provenance;
- allowing evidence events to be rewritten after they are committed;
- full DAW plugin capture;
- neural watermarking;
- replacing copyright registration or legal ownership adjudication.

## V1 acceptance gate

HumanProof V1 is ready for beta when an actual creation session can be recorded, registered, closed, cryptographically verified, linked to an Omni ID, and represented safely on the certificate/public verification flow, with tests for tampering and tenant isolation.
