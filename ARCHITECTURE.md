# Privacy Shield AI — Backend Architecture

> Personal Digital Footprint Risk Intelligence System
> Defensive, consent-first privacy assessment. Users assess ONLY their own footprint.

---

## 0. How to use this file with Antigravity

1. Create an empty repo, put this file at the root as `ARCHITECTURE.md`.
2. Give the agent the **Kickoff Prompt** in Section 16.
3. Build milestone by milestone (Section 15). Do not let the agent skip ahead; each milestone has a "Definition of Done".

---

## 1. Design principles

| Principle | What it means in code |
|---|---|
| Consent first | No scan can start without a signed consent record and a verified ownership proof for each source |
| Data minimisation | Raw PII values are never stored in plaintext; store type, masked preview, and keyed hash |
| Explainable | Every score returns its factor breakdown; no black-box numbers |
| Honest uncertainty | Every finding is tagged `VERIFIED`, `INFERRED` or `UNCERTAIN` with a confidence value |
| Deletable | One call wipes a user and everything derived from them |
| Modular monolith | One deployable FastAPI app, strict module boundaries, workers as separate processes. Easy for a hackathon, easy to split later |
| LLM is a narrator, not a source of truth | Detection and scoring are deterministic or classical ML. The LLM only rewrites already-computed results, and never sees raw PII |

---

## 2. High-level architecture

```
                          ┌──────────────────────┐
                          │   React Frontend     │
                          └──────────┬───────────┘
                                     │ HTTPS (JWT, httpOnly cookie)
                          ┌──────────▼───────────┐
                          │   API Gateway layer  │  FastAPI
                          │ auth · rate-limit ·  │  middleware: request-id, CORS,
                          │ validation · audit   │  security headers, rate limit
                          └──────────┬───────────┘
        ┌─────────────┬──────────────┼───────────────┬──────────────┐
        ▼             ▼              ▼               ▼              ▼
  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────────┐ ┌────────────┐
  │ Identity │ │  Consent & │ │   Scans     │ │  Reports   │ │ Privacy    │
  │ & Auth   │ │  Ownership │ │ Orchestrator│ │  & Export  │ │ Assistant  │
  └──────────┘ └────────────┘ └──────┬──────┘ └────────────┘ └────────────┘
                                     │ enqueue
                          ┌──────────▼───────────┐
                          │ Redis (queue + cache)│
                          └──────────┬───────────┘
                                     │
                ┌────────────────────▼─────────────────────┐
                │          Worker pool (ARQ / Celery)       │
                │                                           │
                │  Fetch → Extract → Detect → Resolve →     │
                │  Graph → Score → Recommend → Report       │
                └───┬──────────────┬──────────────┬─────────┘
                    ▼              ▼              ▼
             ┌───────────┐  ┌────────────┐  ┌──────────────┐
             │ PostgreSQL│  │ S3 / MinIO │  │ ML artifacts │
             │ (+pgcrypto│  │ encrypted  │  │ (models,     │
             │  pgvector)│  │ blobs, TTL │  │  rules YAML) │
             └───────────┘  └────────────┘  └──────────────┘
```

---

## 3. Tech stack (final choices)

| Concern | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 | Typed, async, auto OpenAPI |
| ORM / migrations | SQLAlchemy 2.0 (async) + Alembic | Standard |
| DB | PostgreSQL 16 (+ `pgcrypto`, optional `pgvector`) | Relational findings + graph edges |
| Queue | Redis + ARQ (simple) or Celery (if you want beat scheduling) | Async scans |
| Blob store | MinIO locally, S3 in cloud | Uploaded documents, reports |
| PII detection | **Microsoft Presidio** (wraps spaCy) + custom regex recognizers (Indian formats: phone, Aadhaar-pattern, PAN-pattern, PIN code) | Mature, extensible, explainable |
| NER | spaCy `en_core_web_trf`, optional HF `dslim/bert-base-NER` | Names, orgs, locations |
| Classical ML | scikit-learn (gradient boosting for sensitivity calibration, logistic regression for context) | Explainable |
| Graph | NetworkX in-memory per scan, persisted to Postgres tables | No Neo4j needed for MVP |
| HTML extraction | `httpx` + `selectolax` / `trafilatura`; Playwright only as optional fallback | Fast, light |
| Auth | argon2-cffi, PyJWT, refresh-token rotation | Secure defaults |
| Crypto | `cryptography` (AES-256-GCM envelope encryption) | Field-level encryption |
| LLM | Provider-agnostic `LLMClient` interface (Gemini / Claude / local) | Swap freely |
| Observability | structlog, OpenTelemetry, Prometheus metrics | Debuggable |
| Testing | pytest, pytest-asyncio, hypothesis, schemathesis | Property + API fuzz tests |
| Tooling | uv, ruff, mypy, pre-commit, Docker Compose | Quality gates |

---

## 4. Repository structure

```
privacy-shield-ai/
├── ARCHITECTURE.md
├── docker-compose.yml
├── pyproject.toml
├── alembic/
├── app/
│   ├── main.py                    # app factory, router mounting
│   ├── core/
│   │   ├── config.py              # pydantic-settings
│   │   ├── security.py            # hashing, JWT, token rotation
│   │   ├── crypto.py              # envelope encryption, HMAC hashing, masking
│   │   ├── errors.py              # domain exceptions → HTTP mapping
│   │   ├── logging.py
│   │   ├── rate_limit.py
│   │   └── ssrf_guard.py          # URL safety (see §10)
│   ├── db/
│   │   ├── session.py
│   │   ├── base.py
│   │   └── models/                # one file per aggregate
│   ├── modules/
│   │   ├── auth/                  # router.py, service.py, schemas.py
│   │   ├── consent/
│   │   ├── ownership/             # ownership verification
│   │   ├── sources/               # user-submitted URLs / text / files
│   │   ├── scans/                 # orchestration + state machine
│   │   ├── findings/
│   │   ├── graph/                 # exposure graph + combination risk
│   │   ├── scoring/               # explainable risk engine
│   │   ├── recommendations/       # playbooks + rule engine
│   │   ├── assistant/             # grounded LLM explainer
│   │   ├── reports/               # PDF/JSON/HTML report builder
│   │   ├── monitoring/            # scheduled rescans + diffs
│   │   └── privacy_admin/         # export, delete, audit viewer
│   ├── pipeline/
│   │   ├── fetchers/              # url_fetcher.py, text_fetcher.py, file_fetcher.py
│   │   ├── extractors/            # html.py, pdf.py, docx.py, plain.py
│   │   ├── detectors/             # presidio_engine.py, custom_recognizers.py
│   │   ├── resolvers/             # entity_resolution.py
│   │   └── runner.py              # stage runner with checkpoints
│   ├── ml/
│   │   ├── features.py
│   │   ├── sensitivity_model.py
│   │   └── artifacts/
│   ├── rules/                     # YAML: sensitivities, playbooks, platforms
│   └── workers/
│       ├── settings.py
│       └── tasks.py
└── tests/
    ├── unit/ ├── integration/ ├── security/ └── fixtures/synthetic_personas/
```

Each module follows `router.py → service.py → repository.py`. Routers hold no business logic; services never import FastAPI.

---

## 5. Data model (PostgreSQL)

```
users(id, email_hash, email_enc, password_hash, dek_wrapped, created_at, deleted_at, retention_mode)
consents(id, user_id, version, scope_json, ip_hash, accepted_at, revoked_at)
sources(id, user_id, kind[URL|TEXT|FILE|PLATFORM_EXPORT], label, uri_enc, status,
        ownership_status[UNVERIFIED|PENDING|VERIFIED|SELF_DECLARED], created_at)
ownership_challenges(id, source_id, method[BIO_TOKEN|META_TAG|DNS_TXT|EMAIL_OTP|SELF_DECLARE],
                     token_hash, expires_at, verified_at)
scans(id, user_id, status[QUEUED|FETCHING|ANALYZING|SCORING|DONE|FAILED|CANCELLED],
      stage_checkpoint, mode[STANDARD|EPHEMERAL], started_at, finished_at, error_code)
scan_sources(scan_id, source_id, content_hash, fetched_at, fetch_status)
documents(id, scan_source_id, blob_key, text_len, lang, expires_at)      -- TTL purge job
findings(id, scan_id, source_id, type, category, masked_preview, value_hmac,
         value_enc, span_start, span_end, detector, confidence, evidence_class[VERIFIED|INFERRED|UNCERTAIN],
         visibility, sensitivity, context_flags_json)
entities(id, scan_id, kind[PERSON|EMAIL|PHONE|ORG|LOCATION|HANDLE|ID], canonical_hmac, label_masked)
entity_mentions(entity_id, finding_id)
graph_edges(id, scan_id, src_entity, dst_entity, relation, weight, evidence_finding_ids)
risk_scores(id, scan_id, total, band, confidence, factors_json, combination_json, model_version)
recommendations(id, scan_id, finding_id NULL, playbook_id, priority, effort, impact, status[OPEN|DONE|DISMISSED])
monitor_jobs(id, user_id, cadence, next_run_at, active)
scan_diffs(id, from_scan, to_scan, added_json, removed_json, score_delta)
audit_log(id, actor, action, object_type, object_id, ts, ip_hash, prev_hash, entry_hash)  -- hash chain
```

Key rules:
- `value_enc` is optional. In **EPHEMERAL** mode it is never written.
- `value_hmac` is HMAC-SHA256 with a server-side pepper. It lets us detect "same email appears in 3 sources" without storing the email.
- All FKs `ON DELETE CASCADE` from `users`, so deletion is a single statement plus blob purge.

---

## 6. The analysis pipeline

Each stage is idempotent, checkpointed in `scans.stage_checkpoint`, and can resume after a crash.

```
1 FETCH      Validate URL (SSRF guard), robots/ToS policy check, size/time limits, fetch
2 EXTRACT    HTML/PDF/DOCX → clean text + structural hints (title, meta, visible vs hidden)
3 DETECT     Presidio + custom recognizers + spaCy NER → raw findings with spans
4 CLASSIFY   Map to taxonomy: CONTACT, IDENTITY, LOCATION, FINANCIAL, EDUCATION, EMPLOYMENT, BIOMETRIC_HINT, HANDLE
5 RESOLVE    Entity resolution: collapse duplicates across sources via normalised HMAC
6 GRAPH      Build Exposure Graph, compute combination risk
7 SCORE      Explainable scoring (§8)
8 RECOMMEND  Rule engine selects playbooks, ranks by impact/effort
9 REPORT     Assemble masked report, optional LLM narration
10 PURGE     Apply retention policy (delete raw docs in EPHEMERAL mode immediately)
```

Detection strategy (layered, so each finding knows who found it):
1. Deterministic regex + checksum validators (email, phone via `phonenumbers`, PIN codes)
2. NER models for names/orgs/places
3. Context rules ("contact me at", "DOB:", "my address")
4. A small scikit-learn classifier to **reduce false positives**, using features such as surrounding tokens, position in the document, and whether the text is in a header, footer or body

The `detector` field and `confidence` on each finding come straight from this layering.

---

## 7. Unique features (the stand-out part)

### 7.1 Exposure Graph + Combination Risk (your headline feature)
Entities (name, email, phone, employer, city, college, handle) become nodes. Edges mean "appear together in a source" or "same value in two sources". The system then computes:

- **Linkability**: can a stranger connect source A to source B? (shared handle, email, name+city)
- **Combination multiplier**: e.g. `name + college + city + phone` is more dangerous than the sum of its parts
- **Attack-path summaries**: plain-language chains like *"Your portfolio links your name to your city; your resume adds a phone number"*, with the values masked

### 7.2 Re-identification Uniqueness Score
Estimates how uniquely a combination of quasi-identifiers points to one person, using a k-anonymity-style heuristic. Use a small public lookup (population by city, college size, year of birth bands) in a YAML file.
Output: *"These 4 details together narrow you to roughly 1 in 3,000 people."* Label clearly as an estimate.

### 7.3 Ownership Verification (anti-misuse by design)
Before a URL is scanned, the user proves it is theirs:
- **BIO_TOKEN**: place `shield-verify-<token>` in the profile bio, we fetch and confirm, user removes it
- **META_TAG / DNS_TXT** for personal sites
- **EMAIL_OTP** for email-based sources
- **SELF_DECLARE** only for pasted text or uploaded files (no outbound fetch happens)

This is what keeps the product defensive instead of a lookup tool for other people.

### 7.4 Privacy-by-Design Reports ("Redacted by default")
Findings show `ra****@gm***.com` style previews. The user can click "reveal" (re-decrypts, logged to audit). Reports never contain full values unless explicitly exported.

### 7.5 Ephemeral Mode (zero-retention scan)
Toggle per scan. Text is processed in memory, only masked previews and scores are kept, raw documents and `value_enc` are never persisted. Strong demo moment for judges.

### 7.6 Attacker's-Eye Simulation (defensive)
Rule-based "what could a bad actor attempt" panel, with no real-world action: *Phishing personalisation readiness*, *SIM-swap/KYC-answer readiness*, *Impersonation readiness*, each rated Low/Med/High with the exact factor that drives it and the fix.

### 7.7 Fix-It Playbooks
YAML-driven step-by-step guides per platform (LinkedIn, Instagram, GitHub, X, Google account, generic website). Each playbook has `steps`, `effort_minutes`, `expected_score_gain`. The report shows **"Do these 3 things → score improves by ~X"**, computed by re-running the scorer with the finding removed (a *what-if simulator*).

### 7.8 What-If Simulator
`POST /scans/{id}/simulate` with `{"remove_findings":[...]}` returns the new score and graph without a rescan. Great for an interactive dashboard slider.

### 7.9 Exposure Timeline and Diff Alerts
Monitoring reruns authorised sources, stores `scan_diffs`, and alerts on *new* exposure only, with masked content in notifications.

### 7.10 Tamper-evident Audit Ledger
`audit_log` is hash-chained (`entry_hash = H(prev_hash || row)`). A `/privacy/audit/verify` endpoint proves nothing was altered. Cheap to build, impressive to show.

### 7.11 Synthetic Persona Generator
CLI + endpoint to generate fake people with seeded exposure patterns (using Faker) for demos, tests and benchmarking detector precision/recall. Solves the "consented demo data" requirement in your document.

### 7.12 Optional: Breach Cross-check
User's own email checked against a breach API using privacy-preserving lookups. Feature-flagged since it needs an API key.

---

## 8. Explainable risk scoring engine

Per-finding risk:

```
finding_risk = S × V × C × K

S = sensitivity weight     (0–1, from rules/sensitivity.yaml, calibrated by ML)
V = visibility factor      (public-indexed 1.0, public-unindexed 0.7, semi-public 0.4)
C = context factor         (contact-intent text, recency, prominence on page)
K = confidence             (detector confidence × evidence class multiplier)
```

Aggregate (diminishing returns so 20 low findings don't equal 1 critical):

```
base       = 1 − Π(1 − finding_risk_i)
combo      = graph.combination_multiplier        (1.0 – 1.6)
raw        = min(1, base × combo)
risk_score = round(raw × 100)
privacy_score = 100 − risk_score                 (what the dashboard shows)
band       = LOW <25 · MODERATE <50 · HIGH <75 · CRITICAL ≥75
```

Response always includes:

```json
{
  "privacy_score": 71,
  "band": "MODERATE",
  "confidence": 0.78,
  "factors": [{"finding_id": "...", "type": "PHONE", "S":0.8,"V":1.0,"C":0.9,"K":0.95,"risk":0.68}],
  "combination": {"multiplier": 1.3, "reasons": ["name+phone+city in linked sources"]},
  "method_version": "score-v1",
  "disclaimer": "Estimate based on supplied sources only. A clean result does not prove complete safety."
}
```

`method_version` is stored so old reports stay reproducible.

---

## 9. API surface (v1)

```
AUTH
POST   /v1/auth/register            POST /v1/auth/login
POST   /v1/auth/refresh             POST /v1/auth/logout

CONSENT & OWNERSHIP
GET    /v1/consent/current          POST /v1/consent/accept        POST /v1/consent/revoke
POST   /v1/sources                  GET  /v1/sources               DELETE /v1/sources/{id}
POST   /v1/sources/{id}/ownership/challenge
POST   /v1/sources/{id}/ownership/verify

SCANS
POST   /v1/scans                    body: {source_ids, mode}
GET    /v1/scans/{id}               status + stage progress
GET    /v1/scans/{id}/events        SSE stream of stage updates
POST   /v1/scans/{id}/cancel

RESULTS
GET    /v1/scans/{id}/findings      filters: category, risk, evidence_class
POST   /v1/findings/{id}/reveal     (audited)
GET    /v1/scans/{id}/score
GET    /v1/scans/{id}/graph         nodes + edges for visualisation
GET    /v1/scans/{id}/uniqueness
GET    /v1/scans/{id}/attacker-view
POST   /v1/scans/{id}/simulate
GET    /v1/scans/{id}/recommendations
PATCH  /v1/recommendations/{id}     mark done / dismiss

ASSISTANT
POST   /v1/assistant/ask            body: {scan_id, question}

REPORTS
POST   /v1/scans/{id}/report        format: pdf|html|json
GET    /v1/reports/{id}/download

MONITORING
POST   /v1/monitoring               GET /v1/monitoring/{id}/timeline

PRIVACY ADMIN
GET    /v1/me/export                full data export
DELETE /v1/me                       full erasure
GET    /v1/privacy/audit            GET /v1/privacy/audit/verify

DEV / DEMO
POST   /v1/demo/persona             create synthetic persona and scan it
GET    /healthz   GET /readyz   GET /metrics
```

Conventions: cursor pagination, RFC 7807 problem+json errors, `Idempotency-Key` header on `POST /scans`, request-id on every response.

---

## 10. Security architecture

**Authentication**
- argon2id password hashing
- Access token 15 min (JWT), refresh token 7 days, rotating, stored hashed, reuse detection revokes the family
- Account lockout and exponential backoff on failed logins

**Encryption**
- Envelope encryption: a per-user DEK encrypts sensitive fields (AES-256-GCM). DEKs are wrapped by a master KEK from env / KMS
- TLS everywhere; DB and blob encryption at rest
- HMAC pepper for value hashing, kept separate from the KEK

**SSRF and fetch safety** (critical, because the server fetches user-supplied URLs)
- Allow only `http/https`, resolve DNS and **block private, loopback, link-local and metadata IP ranges** (`10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`, IPv6 equivalents)
- Re-validate after every redirect, cap redirects at 3
- Pin the resolved IP for the request to defeat DNS rebinding
- Max response size (e.g. 5 MB), 10 s timeout, content-type allowlist
- Fetcher workers run in a network-restricted container

**Platform policy**
- Respect `robots.txt` and platform terms. For platforms that block scraping, fall back to **user-uploaded data exports or pasted text** rather than bypassing protections. Never ask for social media credentials

**Application hardening**
- Pydantic strict validation, upload type sniffing plus size limits, antivirus hook optional
- Per-user and per-IP rate limits (Redis token bucket), per-user scan quota
- Prompt-injection defence for LLM: scraped text is wrapped as untrusted data, LLM output is schema-validated, and the LLM has no tools
- Security headers, CORS allowlist, CSRF protection if cookies are used
- Secrets via env or secret manager, never in repo

**Governance**
- Audit every reveal, export, delete, consent change
- Retention TTL job purges documents (default 24 h) and old scans (user-configurable)
- Data export and erasure endpoints are first-class, not afterthoughts

---

## 11. LLM assistant design (grounded, safe)

```
user question
   │
   ▼
Context builder  → pulls ONLY structured, masked facts: finding types, bands,
                   factor breakdown, graph reasons, playbook ids
   │
   ▼
Prompt template  → system rules + facts JSON + untrusted-input delimiter
   │
   ▼
LLMClient.generate()  → response must match a JSON schema
   │
   ▼
Validator  → rejects any output containing unmasked PII patterns (re-run detectors on output),
             or recommendations not present in the playbook library
   │
   ▼
Answer
```

Because recommendations come from the rule library, the LLM cannot invent unsafe advice. A **template fallback** answers when the LLM is down or the validator rejects output, so the product never breaks during a live demo.

---

## 12. Reliability and performance

- Scan **state machine** with checkpoints, retries with backoff per stage (3 tries), dead-letter queue
- Per-source failures never fail the whole scan; partial results are flagged
- Content-hash caching: unchanged source → skip re-analysis
- Models loaded once per worker process, warmed at startup
- SSE for live progress instead of polling
- Concurrency limits per worker; timeouts at every external boundary
- Target for MVP: a typical scan of 5 sources finishes in under 45 seconds

---

## 13. Testing and quality

| Layer | What |
|---|---|
| Unit | Detectors, masking, scoring math, SSRF guard (table-driven attack URLs) |
| Property | Hypothesis: masking never leaks, score is monotonic (adding a finding never lowers risk) |
| Integration | Full pipeline on synthetic personas with expected findings |
| Detector benchmark | Precision / recall / F1 per PII type, printed as a table for your demo |
| Security | SSRF payload suite, auth bypass, IDOR checks (user A can never read user B's scan), schemathesis fuzzing |
| Contract | OpenAPI snapshot test |
| Load | Locust: 50 concurrent scans |

CI gate: ruff, mypy, pytest with coverage over 80%, `pip-audit`.

---

## 14. Deployment (Docker Compose for MVP)

Services: `api`, `worker`, `scheduler`, `postgres`, `redis`, `minio`, `prometheus` (optional), `grafana` (optional).
Environments: `dev` (hot reload, synthetic data on), `prod-like` (TLS via Caddy, secrets from env file).
Later: move to Cloud Run / ECS, managed Postgres, KMS for the KEK.

---

## 15. Build milestones (use these as Antigravity tasks)

| # | Milestone | Definition of Done |
|---|---|---|
| M0 | Scaffold: repo, Docker Compose, config, logging, health endpoints, CI | `docker compose up` gives healthy `api` + `postgres` + `redis` |
| M1 | Auth + DB models + Alembic migrations + crypto helpers | Register/login/refresh work, rotation reuse test passes |
| M2 | Consent + Sources + Ownership verification | A URL source cannot be scanned until verified |
| M3 | Scan orchestrator + state machine + worker + SSE | A dummy pipeline runs end to end with live progress |
| M4 | Fetchers + SSRF guard + extractors | All SSRF attack tests blocked; HTML/PDF/DOCX text extracted |
| M5 | Detection engine (Presidio + custom + NER) + findings storage with masking | Detector benchmark above 0.85 F1 on synthetic set |
| M6 | Entity resolution + Exposure Graph + combination risk | Graph endpoint returns nodes/edges with reasons |
| M7 | Scoring engine + uniqueness + what-if simulator + attacker view | Score factors sum correctly; monotonicity property test passes |
| M8 | Recommendations + playbooks + assistant (grounded LLM + fallback) | Output validator blocks PII leakage test |
| M9 | Reports (HTML/PDF/JSON) + reveal + audit ledger + export/delete | Delete leaves zero rows and zero blobs for the user |
| M10 | Monitoring + diffs + synthetic persona demo + load/security test pass | Full demo script runs in under 3 minutes |

**Hackathon cut line:** if time is short, ship M0–M8 and a minimal M9 (HTML report + delete). Skip monitoring and breach check.

---

## 16. Antigravity kickoff prompt (copy-paste)

```
You are building the backend for "Privacy Shield AI" exactly as specified in ARCHITECTURE.md.

Rules:
- Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, PostgreSQL, Redis + ARQ, uv for deps.
- Follow the repository structure in Section 4. Modules use router → service → repository.
- Build ONE milestone at a time starting with M0. After each milestone: run tests, run ruff and mypy,
  show me the results, and stop for my approval before the next milestone.
- Never store raw PII in plaintext; use the crypto helpers (encrypt, HMAC, mask).
- Never send raw PII to any LLM. Scraped text is untrusted input.
- The SSRF guard in Section 10 is mandatory for every outbound fetch.
- Write tests alongside code. No TODO stubs in finished milestones.
- Use synthetic personas for all fixtures; never use real people's data.

Start with M0 and give me a plan before writing code.
```

---

## 17. Responsible-use guardrails (keep these visible in the product)

- The product assesses the user's **own** footprint only; ownership proof enforces this
- No credential collection, no bypassing platform protections
- Findings are labelled VERIFIED / INFERRED / UNCERTAIN
- Scores are estimates with a published method; a clean report never claims total safety
- Users can export and delete everything at any time
