# Changelog

## 1.2.0 - Frontend F1

- Added the React/Vite TypeScript frontend scaffold, strict API types generated
  from the live OpenAPI contract, and same-origin development proxy.
- Added accessible login/register screens, protected routes, in-memory access
  token storage, cookie-based refresh with single-flight retry, and an
  informative first-run workspace shell.
- Added concurrent-refresh, authentication form, error, and token-storage
  tests; documented frontend setup and frontend/backend integration.
- Scoped the readable CSRF cookie to `/` so the SPA can send refresh/logout
  headers; the HttpOnly refresh cookie remains scoped to `/v1/auth`.

## 1.3.0 - Frontend F2

- Added the versioned consent screen using the backend's current statements and
  scope, with an explicit acceptance action before source workflows are enabled.
- Added user-scoped URL, pasted text, and raw TXT/PDF/DOCX source submission,
  masked source inventory, and source deletion.
- Added URL ownership challenges for profile bio tokens, page meta tags, DNS TXT
  records, and domain email OTP, with instructions, expiry, and verification.
- Added source/consent API flow tests, including raw file body and header checks.

## 1.1.0 - M10

- Added owner-scoped daily/weekly monitoring of eligible sources, periodic ARQ
  dispatch, scheduled scan finalization, and bounded masked exposure diffs.
- Paused monitoring when consent is revoked or a monitored source is no longer
  eligible; retries preserve the scheduled-scan idempotency boundary.
- Removed monitor jobs and their diff history when a monitored source is
  deleted, preventing stale masked data from outliving its source.
- Added seeded synthetic persona generation for CLI and authenticated demo
  scans, with encrypted self-declared source content and idempotent retries.
- Added monitoring migration, consent/ownership/IDOR/diff privacy tests, and
  documented monitoring retention and demo commands.

## 1.0.0 - M9

- Added masked JSON, HTML, and PDF reports with authenticated, audited downloads.
- Added owner-only finding reveal with immediate decryption, no-store responses,
  and audit-chain logging; EPHEMERAL findings remain non-revealable.
- Added a globally hash-chained audit ledger, user-scoped event listing, and
  chain verification. Actor, object, and IP references are keyed hashes.
- Added full user data export with explicitly decrypted source/finding values
  and full account deletion with database cascades.
- Documented that pseudonymous audit entries remain after deletion to preserve
  ledger integrity; added M9 migration and privacy handling documentation.

## 0.9.0 - M8

- Added a persisted `RECOMMENDING` scan stage and YAML-driven playbooks with
  effort, masked evidence, status updates, and score gains recalculated by
  rerunning the scorer with matched finding groups removed.
- Added user-scoped recommendation list/update endpoints and cascade deletion
  with the owning scan.
- Added a grounded assistant endpoint with masked structured context, detected
  PII redaction before provider calls, strict response validation, output PII
  rescanning, and an explicit template fallback.
- Kept external LLM use disabled by default; optional OpenAI-compatible HTTPS
  configuration is environment-only, and assistant exchanges are not persisted.

## 0.8.0 - M7

- Added persisted `score-v1` risk scores with per-finding S/V/C/K factors,
  evidence multipliers, graph combination details, confidence, and risk bands.
- Added authenticated score, uniqueness, defensive attacker-view, and
  what-if simulation endpoints. Simulations validate scan ownership and
  recompute a masked graph and score without persisting changes.
- Added an explicitly labelled type-only uniqueness proxy in YAML, property
  tests for score monotonicity, and scoring-method documentation.

## 0.7.0 - M6

- Added HMAC-based entity resolution, persisted entity mentions, and bounded
  same-source co-occurrence edges with deterministic IDs for safe retries.
- Added a user-scoped Exposure Graph endpoint with masked nodes, evidence IDs,
  source linkability reasons, and a documented heuristic combination multiplier.
- Bounded graph input to 50,000 findings, 2,000 nodes, and 10,000 edges, with
  explicit truncation reporting and tests for resolution, limits, masking, and
  ownership.

## 0.6.0 - M5

- Added Presidio and spaCy NER, custom recognizers, and a scikit-learn
  false-positive context classifier.
- Added the findings table and migration with constrained evidence labels,
  confidence, taxonomy, source spans, masked previews, and keyed HMACs.
- STANDARD findings encrypt values at rest; EPHEMERAL findings omit encrypted
  values. Added a user-scoped, masked findings endpoint with cursor pagination.
- Wired detection into the scan analysis stage and added a synthetic per-type
  precision/recall/F1 benchmark and privacy-focused tests.

## 0.5.0 - M4

- Added bounded HTML, UTF-8 text, PDF, and DOCX extractors, including visible
  and hidden HTML/DOCX text and structural metadata.
- Extended the existing SSRF-safe fetcher to support only the PDF and DOCX
  media types needed for document downloads.
- Wired the scan worker to fetch verified URLs only and decrypt self-declared
  sources in memory; extracted text is not persisted or logged.
- Added per-source processing status, keyed content fingerprints, and partial
  source failure reporting.
- EPHEMERAL scans omit content fingerprints and fetch timestamps; routine HTTP
  client request logs are suppressed to avoid emitting source URLs.
- Added parser limits for extracted characters, PDF pages, and DOCX expanded
  archive size, plus synthetic extraction and worker tests.

## 0.4.0 - M3

- Added consent- and ownership-gated scan creation with per-user idempotency,
  scan status, cancellation, and user-scoped access.
- Added scan/source associations, persisted progress events, stage checkpoints,
  retry attempts, and dead-letter persistence.
- Added ARQ worker and Compose service with three attempts and exponential
  retry delays, dead-letter persistence, and recovery of persisted queued jobs;
  queue failures can be retried using the original idempotency key.
- Added replayable authenticated SSE progress. Progress messages contain no
  source content, URLs, or raw PII.
- Added an explicit M3 orchestration-only pipeline: it exercises the workflow
  but does not fetch or analyze sources, produce findings, or calculate scores.

## 0.3.0 - M2

- Added versioned consent acceptance and revocation, with keyed IP hashes and
  consent-gated source submission and ownership verification.
- Added encrypted URL, pasted-text, and UTF-8/PDF/DOCX source storage with
  upload size/type checks, user-scoped listing, deletion, and scan-eligibility
  checks; file bodies are streamed without plaintext temporary-file spooling.
- Added BIO_TOKEN, META_TAG, DNS_TXT, domain-matched SMTP EMAIL_OTP, and
  self-declared ownership workflows with hashed challenge secrets and bounded
  attempts.
- Pulled the SSRF guard forward for ownership verification: public-IP DNS
  validation and pinning, redirect revalidation, robots.txt enforcement,
  standard-port restrictions, and response size/time/content-type limits.
- Added consent/source/ownership API and regression tests.

## 0.2.0 - M1

- Added async SQLAlchemy auth models and an initial Alembic migration.
- Added Argon2id password hashing, JWT access tokens, rotating refresh tokens
  with reuse detection, cookie CSRF protection, and bounded login lockout.
- Added per-user envelope encryption and peppered HMAC helpers; account emails
  are not stored in plaintext.
- Added auth API routes and tests for registration, login, refresh rotation,
  reuse revocation, encryption, lockout, and migration behavior.

## 0.1.0 - M0

- Scaffolded the FastAPI application, environment configuration, structured
  logging, request IDs, and liveness/readiness endpoints.
- Added a Compose development stack for the API, PostgreSQL 16, and Redis.
- Added CI checks and focused backend tests.
