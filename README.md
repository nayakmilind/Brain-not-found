# Privacy Shield AI

Privacy Shield AI is a consent-first platform for helping people assess and reduce
their own public digital footprint. It does not collect social-media credentials
or bypass platform protections.

## Frontend (F1–F2)

The React/Vite frontend is in `frontend/`. Follow [frontend/README.md](./frontend/README.md)
for Node/pnpm setup and quality commands. The app includes account screens,
versioned consent, source management, and URL ownership verification. For local
development, start the API stack first; Vite proxies `/v1` to
`http://127.0.0.1:8000`. See
[docs/INTEGRATION.md](./docs/INTEGRATION.md) for auth cookies, CSRF, and
deployment guidance. Scan, findings, and report screens are not yet available.

## M0 local setup

Requirements: Docker Compose and `uv` with Python 3.12 available.

1. Copy `.env.example` to `.env`.
2. Generate three independent 32-byte secrets:

   ```powershell
   uv run python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
   ```

   Put separate generated values in `MASTER_KEK_B64`, `HMAC_PEPPER_B64`, and
   `JWT_SECRET_B64`. Never reuse or commit them. For local HTTP development,
   keep `COOKIE_SECURE=false`; use `true` behind HTTPS.

3. If changing the PostgreSQL password, update both `POSTGRES_PASSWORD` and the
   password component in `DATABASE_URL`; URL-encode special characters in the URL.
4. Start the API, scan worker, and their dependencies:

   ```powershell
   docker compose up --build
   ```

5. Check liveness and dependency readiness:

   ```powershell
   Invoke-RestMethod http://localhost:8000/healthz
   Invoke-RestMethod http://localhost:8000/readyz
   ```

The API listens on port 8000 by default. PostgreSQL and Redis are available only
to Compose services and are not published on host ports. The API container runs
Alembic migrations before starting the server; the ARQ worker starts after the
API is healthy.

## M1 authentication

The initial authentication endpoints are:

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`

Access tokens are short-lived JWTs. Rotating opaque refresh tokens are stored
only as keyed hashes and delivered in an HttpOnly cookie; refresh/logout require
a matching double-submit CSRF token. Account emails are HMAC-indexed and
field-encrypted with a per-user data key wrapped by the configured master key.
Failed logins trigger bounded exponential lockout. Run migrations locally with
`uv run alembic upgrade head` after configuring `.env`.

## M2 consent, sources, and ownership

These endpoints require a bearer access token, except for the public current
consent-version document. A user must accept the current consent version
(`2026-03`) before adding a source or starting ownership verification. Consent
is versioned, records a keyed hash of the requester's IP address, and can be
revoked; revocation blocks new source submissions and verification.

- `GET /v1/consent/current-version` and `GET /v1/consent/current`
- `POST /v1/consent/accept` and `POST /v1/consent/revoke`
- `POST /v1/sources`, `POST /v1/sources/file`, `GET /v1/sources`
- `DELETE /v1/sources/{source_id}`
- `POST /v1/sources/{source_id}/ownership/challenge`
- `POST /v1/sources/{source_id}/ownership/verify`

URL, label, pasted text, and uploaded file contents are encrypted with the
user's envelope-encryption key before persistence. Outside encrypted payloads,
the database stores only generic previews, source type, byte count, and workflow
status. API responses expose generic previews and workflow status by default.
Pasted text and uploads are self-declared and never fetched. URL sources remain
unverified until a BIO_TOKEN, META_TAG, DNS_TXT, or domain-matched EMAIL_OTP
challenge succeeds; they are not eligible for a scan before then.

File uploads stream as a raw request body (not multipart) to avoid plaintext
temporary-file spooling. Send `X-Source-Extension: txt|pdf|docx`, an optional
`X-Source-Kind: FILE|PLATFORM_EXPORT`, and a percent-encoded UTF-8
`X-Source-Label` header; the body is size-capped while streaming and validated
by file signature/container structure before encryption.

Verification HTTP requests use the SSRF guard: only standard HTTP(S) ports,
public DNS answers, a pinned resolved IP, HTTPS-preserving and revalidated
redirects, bounded response size/time, supported content types, and a
fail-closed `robots.txt` check. The fetcher does not use ambient proxy settings
or source-site credentials. If a platform blocks access, use a pasted text or
user-uploaded export instead.

EMAIL_OTP is disabled unless `SMTP_HOST` and `SMTP_FROM` are configured. SMTP
STARTTLS is mandatory; optional SMTP credentials must be set as a pair. The
user's submitted email and OTP are not persisted; only the keyed OTP hash is
stored. Configure the `SOURCE_*` values and SMTP settings through environment
variables, never source code.

## M3 scan orchestration

The scan API requires a bearer token, active consent, and an `Idempotency-Key`
header. Every submitted source must belong to the authenticated user and be
active; URL sources must have verified ownership. Pasted text and uploaded
files remain self-declared and are never fetched.

- `POST /v1/scans` with `{"source_ids": ["..."], "mode": "STANDARD"}` or
  `"EPHEMERAL"` queues an idempotent scan.
- `GET /v1/scans/{scan_id}` returns its state, current checkpoint, retry count,
  and result availability.
- `GET /v1/scans/{scan_id}/events` streams replayable progress events as SSE.
  Supply `Last-Event-ID` to resume after a previously received event.
- `POST /v1/scans/{scan_id}/cancel` cancels a queued or active scan.

The ARQ worker persists stage checkpoints and progress events, retries
unexpected failures up to three times with backoff, and records exhausted jobs
in the dead-letter table. A periodic dispatcher recovers persisted queued scans
after an API/worker interruption, using generation-specific deterministic job
IDs to avoid duplicate work. Events contain fixed status messages only, never
source text or URLs. M3 established orchestration; M4 added safe fetching and
extraction, M5 added masked findings, and M6 adds entity resolution and the
Exposure Graph; M7 adds explainable scoring and estimates. Scans without the
M5 detection pipeline report
`result_state: NOT_GENERATED`; this is not a clean privacy report and contains
no findings or score.

## M4 fetching and extraction

The worker now processes only active, eligible sources: verified URL sources go
through the SSRF-safe fetcher, while pasted text and uploaded files are
decrypted and read locally without any outbound request. The fetcher continues
to enforce public-address resolution and pinning, redirect revalidation,
robots.txt, standard ports, response size/time limits, and the HTML, plain text,
PDF, and DOCX content-type allowlist.

HTML extraction separates visible from hidden text and captures titles/meta
without executing page content. UTF-8 text, PDF, and DOCX extractors enforce
character/page/expanded-archive limits. Extracted text and metadata stay in
worker memory; STANDARD scans persist only a keyed content fingerprint,
timestamp, and processing status. EPHEMERAL scans omit the fingerprint and
timestamp as well. API and worker logging suppress routine HTTP client request
records so source URLs are not emitted in access logs. Individual source fetch
or extraction failures are flagged as `PARTIAL_SOURCE_FAILURE` without failing
the whole scan.

Configure `EXTRACTION_MAX_CHARACTERS`, `EXTRACTION_MAX_PDF_PAGES`, and
`EXTRACTION_MAX_DOCX_UNCOMPRESSED_BYTES` to set parser limits.

## M5 detection and findings

The analysis stage runs Presidio's English recognizers with spaCy NER, plus
custom validators for profile handles, postal codes, and dates of birth. A
small scikit-learn context classifier, fit from fixed synthetic context
examples, filters ambiguous custom matches. It is an MVP filter, not a
production-trained general-purpose classifier.
Findings are labelled with confidence and `VERIFIED`, `INFERRED`, or
`UNCERTAIN` evidence, and classified into the architecture's privacy taxonomy.
`VERIFIED` means a deterministic format validator matched the observed text;
it does not verify ownership of an account or confirm that a value is current.

Findings persist only a masked preview, a peppered HMAC, source span and
detector metadata. STANDARD scans additionally encrypt the value for a future
audited reveal flow; EPHEMERAL scans never write that encrypted value. The
user-scoped `GET /v1/scans/{scan_id}/findings` endpoint returns masked results
only, with category/evidence filters and cursor pagination. M6 added entity
resolution and the Exposure Graph; M7 adds explainable scoring and estimates. A
`GENERATED` result is not proof of total safety.
The benchmark uses synthetic values only and reports precision, recall, and F1
per detected type.

## M6 entity resolution and Exposure Graph

The scan's graph stage resolves findings with the same type-scoped HMAC into a
single entity node. Nodes retain only the entity kind, masked label, and HMAC;
mentions and same-source co-occurrence edges reference finding/source IDs, not
raw values. The user-scoped `GET /v1/scans/{scan_id}/graph` endpoint returns
masked nodes, edges, evidence IDs, source counts, and plain-language reasons.
Repeated masked entities across sources are identified as linkability paths.

The combination multiplier is a heuristic estimate from distinct entity-kind
pairs and entities repeated across sources, bounded to 1.0–1.6. It is one
factor in the M7 privacy score and does not prove a real-world attacker can
identify someone. If construction is truncated, the graph uses the maximum
multiplier conservatively.
Graph construction is bounded to 2,000 nodes and 10,000 edges per scan; the
graph stage examines at most 50,000 findings. The response sets its `truncated`
flag if any cap is exceeded. A truncated graph is incomplete and should not be
read as a complete account of exposures.

## M7 scoring and estimates

The scan's scoring stage stores an explainable risk score with per-finding
`S`, `V`, `C`, and `K` factors, the graph multiplier, confidence, band, and
`score-v1` method version. `GET /v1/scans/{scan_id}/score` returns the masked
factor breakdown. The scoring assumptions and limitations are documented in
[`docs/SCORING.md`](./docs/SCORING.md).

- `GET /v1/scans/{scan_id}/uniqueness` returns a very-low-confidence,
  type-only heuristic estimate; it does not compare actual values against a
  population dataset.
- `GET /v1/scans/{scan_id}/attacker-view` returns rule-based, defensive
  readiness indicators and fixes, with masked evidence.
- `POST /v1/scans/{scan_id}/simulate` removes selected finding IDs in memory
  and recomputes both score and graph without a rescan or database write.

The score is based on the submitted sources only. A low score or empty finding
set does not prove complete safety.

## M8 recommendations and assistant

The `RECOMMENDING` scan stage loads the YAML playbooks in
[`app/data/playbooks.yaml`](./app/data/playbooks.yaml), groups matching masked
findings, and reruns the scorer with each group removed to calculate the
possible privacy-score gain. Verified URL hosts are mapped in memory to
LinkedIn, Instagram, GitHub, X, Google account, or generic website guidance;
other source types receive generic type-specific playbooks. URL values remain
encrypted and are not persisted in platform metadata. Gains are based only on
the supplied sources and the current scoring method.

- `GET /v1/scans/{scan_id}/recommendations` returns user-scoped playbooks,
  masked evidence previews, effort, estimated gain, and status.
- `PATCH /v1/recommendations/{recommendation_id}` accepts `OPEN`, `DONE`, or
  `DISMISSED`; records are scoped to their scan owner and are deleted with the
  scan.
- `POST /v1/assistant/ask` accepts a completed `scan_id` and a question. The
  assistant receives structured report facts and masked previews only; detected
  PII in the question is redacted before any provider call. The model selects a
  report-explanation focus and active playbook IDs rather than writing free-form
  advice; the server renders the answer from trusted templates and playbook
  content, and provider output is schema-validated and rescanned for PII.

The assistant uses a deterministic template by default. An operator may
explicitly enable an OpenAI-compatible HTTPS endpoint using
`ASSISTANT_ENABLED`, `ASSISTANT_BASE_URL`, `ASSISTANT_API_KEY`, and
`ASSISTANT_MODEL`. Provider credentials remain in environment variables; no
provider is configured by default. Provider failures, invalid output, or
detected PII cause a disclosed template fallback. Assistant questions and
responses are not persisted. Even when an operator enables a provider, a caller
must set `allow_external_processing: true` for that request; otherwise the
assistant uses the local template fallback.

## M9 reports and privacy controls

- `POST /v1/scans/{scan_id}/report` creates a masked JSON, HTML, or PDF report;
  `GET /v1/reports/{report_id}/download` is user-scoped and audited.
  Reports support at most 10,000 findings; PDF tables show at most 1,000 and
  identify that limit, while JSON and HTML include the full supported set.
- `POST /v1/findings/{finding_id}/reveal` decrypts a STANDARD finding for its
  owner only and records the reveal in the tamper-evident audit chain.
  EPHEMERAL findings cannot be revealed because their values are not persisted.
- `GET /v1/privacy/audit` lists the authenticated user's pseudonymous audit
  events. `GET /v1/privacy/audit/verify` verifies the complete hash chain.
- `GET /v1/me/export` returns a no-store JSON export, including decrypted
  source content and any persisted finding values. Treat the download as
  sensitive and store it securely. Exports are capped at 50 MiB.
- `DELETE /v1/me` deletes the account and cascades its database-owned content,
  reports, and credentials. A pseudonymous, non-FK audit trail remains to
  preserve hash-chain integrity; see [`docs/PRIVACY.md`](./docs/PRIVACY.md).

## M10 monitoring and synthetic demos

- `POST /v1/monitoring` enables a daily or weekly rescan of the sources from a
  completed scan. Scheduled scans reuse the normal consent, ownership, and
  source-eligibility checks. Revoked consent or an ineligible source pauses the
  monitor; `GET /v1/monitoring/{monitor_id}/timeline` is owner-scoped.
- The ARQ worker checks due monitors every five minutes. It stores diffs with
  masked finding previews and score changes only; new-exposure alert details in
  the timeline are masked and bounded, with truncation disclosed. No external
  notification channel is configured.
- `POST /v1/demo/persona` creates a seeded synthetic persona source and queues
  a STANDARD scan for the authenticated user. It requires current consent and
  is idempotent by user, seed, and pattern. The source is self-declared,
  encrypted at rest, and never fetched from the network.
- Generate local synthetic text without creating an account or scan:

  ```powershell
  uv run python -m app.modules.demo.cli --seed 42 --pattern all
  ```

Deleting any monitored source removes that monitor and its diff history;
account deletion removes all monitoring data. Production-scale load and
container validation still require the documented Docker/Locust environment.

## Quality checks

```powershell
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy app
uv run pytest
uv run pip-audit
uv run alembic history
```

## Architecture

The backend is a modular FastAPI application. The local stack contains the API,
an ARQ scan worker, PostgreSQL 16, and Redis; additional storage and monitoring
services will be introduced with the milestones that use them. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the complete design and milestone plan.
