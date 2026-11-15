# Privacy and data handling

Privacy Shield AI scans only user-submitted sources that pass the existing
consent and ownership gates. Pasted content and uploads are self-declared; they
are not fetched. This document describes the backend behavior implemented
through M10.

## Storage and encryption

- Account email, source labels, URLs, source contents, and STANDARD finding
  values are field-encrypted with AES-256-GCM using the user's wrapped data
  key. Source and finding values are decrypted only for the authenticated
  user's explicit operations.
- Finding records also store a masked preview and a keyed HMAC to support
  matching without persisting plaintext. EPHEMERAL finding values are never
  encrypted or written; they cannot be revealed later.
- Scan results, graphs, scores, recommendations, and generated reports are
  stored in the database. Reports include masked finding previews, not
  decrypted finding values.
- Monitoring metadata records cadence, timestamps, status, and relationships
  to the user's scans and sources. Exposure diffs store only finding types,
  masked previews, confidence/evidence labels, identifiers, score deltas, and
  truncation state; HMACs and encrypted finding values are not copied into
  monitoring records.
- Demo personas are generated locally from a caller-provided seed. Their
  source content is synthetic, self-declared, and encrypted using the same
  per-user key as other pasted text; it is never fetched from the network.
- This implementation stores encrypted uploads and generated report files in
  PostgreSQL; it does not yet use an external blob store.

## Reports, reveal, and export

Reports are generated for completed scans in JSON, HTML, or PDF format and are
masked by default. Download access is scoped to the report's scan owner and is
audited. Reveal decrypts one STANDARD finding for its owner, records the reveal
event, and returns it with `Cache-Control: no-store`; reveal values are not
written to the audit ledger.

The authenticated data export is intentionally more sensitive than a report
and capped at 50 MiB.
It contains decrypted source URLs, labels, and contents, plus any persisted
finding values. Passwords, refresh-token secrets, and encryption keys are
excluded. The export response is no-store; users should securely store or delete
the downloaded file themselves.

## Audit retention

The audit ledger is a single hash chain. It records action names, object types,
timestamps, and keyed hashes of actor, object reference, and client IP; it does
not store raw finding values, source URLs, or IP addresses. The actor reference
is a keyed pseudonym, not a foreign key to the account.

Account deletion removes user-owned rows and their cascaded reports, sources,
scans, findings, and credentials. The pseudonymous audit entries are retained
without a direct account identifier so the hash chain remains verifiable.
They are not returned by the deleted user's account because that account no
longer exists. The audit verification endpoint checks the complete ledger.

## Deletion and limits

`DELETE /v1/me` removes the account in one database transaction; the database
foreign keys cascade through its content. A deletion event is added to the
audit chain in the same transaction. The current backend has no external user
blob store, third-party report archive, or monitoring blobs to purge. Any
export already downloaded by the user cannot be deleted by the service.
Deleting a monitored source removes its associated monitoring job and diff
history, since the old baseline no longer represents the set of sources being
monitored. Deleting the user also cascades through monitoring jobs and diffs.
Monitoring pauses when consent is revoked or any monitored source becomes
ineligible.

The service's estimates apply only to submitted sources. A report without
findings does not establish that the user's complete public footprint is safe.
