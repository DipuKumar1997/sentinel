# SentinelMail AI

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**
Prototype for Smart India Hackathon 2026 — Problem Statement **SIH26106**.

This README is written to be read top to bottom by someone who has
never seen this codebase before. If you just want to run it, skip to
[Quickstart](#quickstart-docker). If you want to understand *how it
works* -- which models run, which endpoints need what kind of
credential, how a submitted email turns into a risk score -- read
[How the system works, end to end](#how-the-system-works-end-to-end).

---

## Table of contents

- [Quickstart (Docker)](#quickstart-docker)
- [The three ways an email gets into the system](#the-three-ways-an-email-gets-into-the-system)
- [How the system works, end to end](#how-the-system-works-end-to-end)
- [The two ML models, and why there are two](#the-two-ml-models-and-why-there-are-two)
- [Every endpoint and what credential it needs](#every-endpoint-and-what-credential-it-needs)
- [Training the text-content model on real data](#training-the-text-content-model-on-real-data)
- [Database schema at a glance](#database-schema-at-a-glance)
- [Full file manifest](#full-file-manifest)
- [Forensic Intelligence](#forensic-intelligence-attribution-without-overclaiming)
- [Running tests](#running-tests)
- [Honesty notes](#honesty-notes-things-intentionally-not-faked)
- [What's still open](#whats-still-open)

---

## Quickstart (Docker)

```bash
cp .env.example .env
# edit SECRET_KEY at minimum before anything beyond local testing
docker compose up --build
```

This starts five containers:

| Service | What it is | URL |
|---|---|---|
| `api` | FastAPI application | http://localhost:8000 (docs at `/docs`, dashboard at `/ui/`) |
| `worker` | Celery worker (scaffolded, not yet used by the sync ingestion pipeline) | -- |
| `db` | PostgreSQL 16 | localhost:5432 |
| `redis` | Redis (Celery broker/backend) | localhost:6379 |
| `pgadmin` | Postgres admin UI | http://localhost:5050 (login: `admin@example.com` / `adminpassword`, both overridable in `.env`) |

Migrations and RBAC role/permission seeding run automatically when the
`api` container starts (see `docker-compose.yml`'s `command:`).

**If you've previously run a *different* project's Postgres in the same
Docker environment**, make sure `docker volume ls` doesn't show a
leftover `pgdata` volume with different credentials baked in --
Postgres only initializes a data directory once; if the volume already
has data in it (from anything, ever), it silently ignores your current
`.env` values. `docker compose down -v` wipes the named volumes if you
need a truly clean slate.

## The three ways an email gets into the system

| Mode | How it works | Status |
|---|---|---|
| **1. Authenticated human upload** | A logged-in user (JWT from `/auth/login`) drags a `.eml`/`.msg` file onto the dashboard, or calls `POST /ingestion/eml` directly with a Bearer token. |  Implemented |
| **2. Programmatic / API key** | A security tool or mail gateway calls `POST /ingestion/eml` with an `X-API-Key` header instead of a JWT -- no human login involved. Keys are created via `POST /api-keys` (org_admin+ only) and are tied to a dedicated, non-loginable "service account" so cases are still attributable. See `app/services/api_key_service.py`. |  Implemented |
| **3. Forward-to-mailbox** | An org forwards suspicious mail to a dedicated inbox (e.g. `security@yourcompany.com`); a Celery beat task polls it over IMAP every 2 minutes and turns each new message into a case automatically. Handles both "forward as attachment" (extracts the real original message) and plain inline forwarding. Defaults to polling a dedicated `Sentinel_Intake` label rather than `INBOX`, to avoid ingesting an entire pre-existing mailbox's history on first setup. **Automatically emails the HTML+PDF report back to whoever forwarded the message** (same mailbox, same App Password, sent via SMTP). See `docs/mailbox_forwarding_setup.md` for a full Gmail walkthrough. |  Implemented |

Both implemented modes end up calling the exact same function,
`app/services/ingestion.py::ingest_email_and_create_case()` -- the only
difference is *who's allowed to call it and how they prove it* (see
`app/security/deps.py::get_current_actor`, which accepts either a JWT
or an API key and resolves both to the same `ActorContext`).

## How the system works, end to end

```
submitted .eml/.msg bytes
        │
        ▼
1. EVIDENCE PRESERVATION (app/services/evidence_storage.py)
   SHA-256 hash computed and the raw bytes written to disk BEFORE
   anything else happens -- even if parsing fails later, this hash
   is still recorded (chain of custody).
        │
        ▼
2. FORENSIC PARSING (app/services/eml_parser.py or msg_parser.py)
   Both formats normalize into the same ParsedEmail shape: headers
   (verbatim, in order), the reconstructed Received: hop chain,
   sender identity claims, body text/HTML, attachments.
        │
        ▼
3. AUTHENTICATION EVIDENCE (app/services/auth_results.py)
   Reads SPF/DKIM/DMARC verdicts from the Authentication-Results
   header if present; falls back to a live DNS lookup for SPF/DMARC
   policy presence if that header is missing.
        │
        ▼
4. IOC EXTRACTION (app/services/ioc_extraction.py)
   Domains, IPs, URLs, and attachment SHA-256 hashes are pulled out
   and normalized into IOCRecord rows.
        │
        ▼
5. THREAT-INTEL ENRICHMENT (app/services/threat_intel.py)
   Every domain/IP IOC is checked against an always-on offline
   heuristic provider, plus VirusTotal/AbuseIPDB/IPinfo IF you've
   configured their API keys in .env (skipped entirely otherwise --
   never fabricated).
        │
        ▼
6. ANALYSIS ENGINES (app/services/analysis_engines/*.py + the 2 ML
   models below) -- each independently emits Finding objects with a
   severity, confidence, and human-readable description. No engine
   sees or depends on any other engine's output.
        │
        ▼
7. RISK FUSION (app/services/risk_fusion.py)
   All findings combined into one 0-100 score via a transparent,
   auditable weighted-sum formula (NOT a black-box ensemble) --
   every point of the score traces back to a specific finding.
        │
        ▼
8. CAMPAIGN CORRELATION (app/services/campaign_correlation.py)
   Checks whether this case shares an IOC with any other recent case
   in the same organization; if so, groups them into a Campaign and
   adds graph edges (GraphEntity/GraphRelationship).
        │
        ▼
   Case saved, ready to browse/export via the dashboard or API.
```

Steps 1-8 all happen inside **one database transaction** per
submission (see `ingest_email_and_create_case()`) -- a submitted email
either produces a fully-analyzed case or an explicit error; there's no
partially-analyzed state visible through the API.

## The two ML models, and why there are two

This project deliberately runs **two separately-trained models**, not
one, because they look at different evidence and have different data
provenance -- combining them into a single model would hide which
signal actually drove a prediction.

| | `ml_scoring_structural.py` | `ml_scoring_text.py` |
|---|---|---|
| **Looks at** | Structural/header features: SPF/DKIM/DMARC fail count, urgency-keyword count, display-name/domain mismatch, URL count, attachment presence | The raw TEXT content: email subject + body |
| **Trained on** | **Synthetically generated** feature combinations (`scripts/train_model.py`) -- no dataset exists that pairs real SPF/DKIM outcomes with ground-truth phishing labels | **Real, publicly available labeled emails** -- ~82,000 real emails across 6 academic corpora (`scripts/train_text_model.py` + `data/README.md`) |
| **Model type** | Logistic Regression (or a hand-weighted heuristic fallback if untrained) | TF-IDF + Logistic Regression |
| **Shipped trained in this repo?** | Yes (`app/ml_models/phishing_classifier.joblib`, small, included) | **No** -- you train it yourself (see below); until you do, this model contributes nothing and no finding is fabricated in its place |
| **Finding engine name** | `ml_model_structural` | `ml_model_text` |

Both feed into the same risk-fusion step as ordinary `Finding` objects
(`app/services/ml_common.py::ModelOutput` is the shared type both use).
Neither is ever the sole basis for a verdict -- see
`docs/threat_model.md` for the full "what does/doesn't this mean"
discussion.

## Every endpoint and what credential it needs

| Endpoint | Method | Credential | Notes |
|---|---|---|---|
| `/api/v1/auth/register` | POST | None | Rate-limited 10/min. First registrant of a brand-new organization becomes `org_admin`; joining an existing org gives `employee`. |
| `/api/v1/auth/verify-email` | POST | None (verification token from registration) | |
| `/api/v1/auth/login` | POST | None (email+password) | Rate-limited 10/min. Locks account for 15 min after 5 failed attempts. |
| `/api/v1/auth/refresh` | POST | Refresh token (rotates on use) | |
| `/api/v1/auth/me` | GET | **JWT** | |
| `/api/v1/ingestion/eml`, `/ingestion/msg` | POST | **JWT OR `X-API-Key`** | The only endpoints accepting an API key. |
| `/api/v1/cases`, `/cases/{id}`, `/cases/{id}/risk-score`, `/cases/{id}/findings` | GET | **JWT** | Always scoped to the caller's own organization. |
| `/api/v1/cases/{id}/report?format=html\|pdf` | GET | **JWT** | |
| `/api/v1/campaigns`, `/campaigns/{id}/cases` | GET | **JWT** | |
| `/api/v1/api-keys` | POST/GET | **JWT, role ≥ org_admin** | Creating/listing API keys. |
| `/api/v1/api-keys/{id}` | DELETE | **JWT, role ≥ org_admin** | Revoke a key. |
| `/api/v1/users` | GET | **JWT, role ≥ org_admin** | List colleagues in your org. |
| `/api/v1/users/{id}/role` | PATCH | **JWT, role ≥ org_admin** | Promote/demote a colleague's role. |
| `/api/v1/mailboxes` | POST/GET | **JWT, role ≥ org_admin** | Register/list forward-to-mailbox intake (see `docs/mailbox_forwarding_setup.md`). |
| `/api/v1/mailboxes/{id}/enable`, `/disable` | PATCH | **JWT, role ≥ org_admin** | Toggle polling. |
| `/api/v1/mailboxes/{id}` | DELETE | **JWT, role ≥ org_admin** | |
| `/api/v1/mailboxes/{id}/poll-now` | POST | **JWT, role ≥ org_admin** | Synchronous poll, for testing without waiting for the schedule. |
| `/api/v1/cases/{id}/origin` | GET | **JWT** | Earliest Reliable External Origin IP, confidence, and reasoning. |
| `/api/v1/cases/{id}/ip-intelligence` | GET | **JWT** | ASN/ISP/hosting/reverse-DNS per IP IOC on the case. |
| `/api/v1/cases/{id}/dns-observations` | GET | **JWT** | Every passive DNS query performed, including failures. |
| `/api/v1/cases/{id}/domain-intelligence/{domain}` | GET | **JWT** | On-demand WHOIS lookup (not run automatically — see below). |
| `/api/v1/cases/{id}/blockchain-verify` | GET | **JWT** | Compares current evidence hash against the anchored hash. |
| `/api/v1/organizations/blockchain-verify` | GET | **JWT** | Verifies the entire organization's hash chain, not just one case. |
| `/api/v1/healthz` | GET | None | |
| `/ui/` | GET | None (the page itself; its own API calls need a JWT) | The dashboard. |
| `/docs` | GET | None | Interactive OpenAPI docs. |

Role hierarchy, low to high: `employee` < `security_analyst` <
`investigator` < `soc_admin` < `org_admin` < `platform_admin` (see
`app/security/rbac.py`).

## Training the text-content model on real data

```bash
pip install -e ".[dev]"
python -m scripts.fetch_datasets      # downloads ~82,000 real labeled emails (see data/README.md)
python -m scripts.train_text_model    # trains, prints a dataset + accuracy report, saves the model
```

This runs entirely on CPU in well under a minute (TF-IDF + Logistic
Regression, not a neural network) -- a GPU buys you nothing for this
specific model. The training script prints, every time you run it,
exactly which dataset files and how many rows from each went into the
model, plus a held-out classification report, so you never have to
take the model's quality on faith.

Want to add the Kaggle datasets you have access to? Drop the CSVs into
`data/raw/kaggle/` and re-run `train_text_model.py` -- see
`data/README.md` for the exact column-name requirements and which
Kaggle datasets we expect to work out of the box.

## Database schema at a glance

41 tables across 8 model modules -- see `docs/architecture.md` section
5 for the full design rationale (UUID PKs, append-only audit/history
tables, content-addressed evidence). Quick map of what's in each file:

| Model file | Tables |
|---|---|
| `organization.py` | organizations |
| `rbac.py` | roles, permissions, role_permissions |
| `user.py` | users, email_verification_tokens, refresh_tokens |
| `case.py` | mailboxes, cases, case_status_history, notes, tags, case_tags |
| `evidence.py` | evidence_objects, evidence_hashes, retention_policies |
| `email.py` | email_messages, email_headers, received_hops, sender_identities, authentication_results |
| `ioc.py` | domains, ips, urls, attachments, ioc_records, threat_intelligence_observations |
| `analysis.py` | analysis_runs, analysis_findings, model_predictions, risk_scores |
| `campaign.py` | campaigns, campaign_memberships, graph_entities, graph_relationships |
| `alert.py` | alerts, report_templates, reports, audit_logs, api_keys, notification_events |

Run `alembic upgrade head` (done automatically in Docker) to
materialize this schema against your own Postgres instance.

## Full file manifest

```
.env.example              Every environment variable, with dev-only defaults commented
.gitignore, .dockerignore Standard excludes; notably excludes data/raw/*.csv and the
                           trained text_content_classifier.joblib (both regenerable)
docker-compose.yml        api + worker + db + redis + pgadmin, 5 services
docker/Dockerfile         Single-stage Python 3.12-slim image
pyproject.toml            All dependencies; `pip install -e ".[dev]"` installs everything
Makefile                  Shortcuts: make install/test/run/migrate/seed/lint/docker-up
LICENSE                   MIT
README.md                 This file
CHANGELOG.md              Full build history, chronological, most recent first
NEXT_STEPS.md             What's genuinely still open (not a gap list in disguise)
PROJECT_PROGRESS.json     Machine-readable phase/status tracker

app/
  main.py                 FastAPI app assembly: middleware, rate limiter, router
                           registration, /ui static mount
  core/
    config.py              Pydantic Settings -- every env var, single source of truth
    limiter.py              Shared slowapi Limiter instance (must be one instance for
                             both the exception handler and the per-route decorators)
  db/
    base_class.py           Declarative Base + UUIDPKMixin/TimestampMixin
    session.py               Async engine + get_db() FastAPI dependency
    seed.py                   Idempotent RBAC role/permission seeding (writes directly
                               to the role_permissions join table -- see CHANGELOG for
                               why, re: an async lazy-load bug this avoids)
  ml_models/
    phishing_classifier.joblib          Structural model, trained on synthetic data (included)
    text_content_classifier.joblib      Text model, trained on real data (NOT included --
                                         you train this yourself, see above)
  models/                  8 files, 41 SQLAlchemy ORM models total (see table above)
  schemas/                 Pydantic request/response models, one file per feature area
  security/
    passwords.py             Argon2id hashing
    tokens.py                 JWT access tokens + opaque rotating refresh tokens
    rbac.py                    require_roles()/require_min_role() FastAPI dependencies
    deps.py                     get_current_user (JWT-only) and get_current_actor
                                 (JWT OR API key) -- the latter used only by ingestion
  services/
    eml_parser.py             RFC 5322/MIME parsing
    msg_parser.py              Outlook .msg parsing -> same ParsedEmail shape
    auth_results.py            SPF/DKIM/DMARC header parsing + live DNS fallback
    ioc_extraction.py          Domain/IP/URL/attachment-hash extraction
    dataset_loader.py          Harmonizes any labeled-email CSV into (text, label)
    ml_common.py                Shared ModelOutput type for both ML models
    ml_features.py               Structural feature vector extraction (training +
                                  inference share this, so they can't drift apart)
    ml_scoring_structural.py      Model 1: structural/header features (synthetic-trained)
    ml_scoring_text.py             Model 2: raw text content (real-data-trained)
    threat_intel.py                Offline heuristic + optional VirusTotal/AbuseIPDB/IPinfo
    evidence_storage.py             Content-addressed, path-traversal-guarded storage
    campaign_correlation.py          Shared-IOC campaign detection + graph building
    report_generator.py               HTML (Jinja2) + native PDF (fpdf2) report rendering
    risk_fusion.py                     Explainable score fusion
    auth_service.py                     Register/login/verify/refresh/lockout logic
    api_key_service.py                   API key generation/verification + service-account
                                          user creation
    ingestion.py                          Orchestrates the entire pipeline end to end
    audit.py                               Append-only audit log writer
    analysis_engines/
      header_forensics.py                  SPF/DKIM/DMARC fail, display-name mismatch, etc.
      url_domain_analysis.py                 Raw-IP links, shorteners, suspicious TLDs
      threat_intel_engine.py                  Converts threat-intel observations to findings
  api/routers/
    auth.py, cases.py, ingestion.py, reports.py, campaigns.py,
    api_keys.py, user_management.py, health.py    One file per feature area
  workers/
    celery_app.py            Celery instance (scaffolded; ingestion runs synchronously
                              today, not yet offloaded to a background task)

frontend/
  index.html                 The entire dashboard: login/register, drag-and-drop
                              upload, case list, findings detail, HTML/PDF report
                              links, campaigns list. Single file, vanilla JS, no
                              build step. Served at /ui/ via FastAPI StaticFiles.

scripts/
  fetch_datasets.py           Downloads the 6 real datasets (see data/README.md)
  train_model.py               Trains the SYNTHETIC structural model
  train_text_model.py           Trains the REAL text-content model

data/
  README.md                   Exact provenance of every training dataset -- read this
                               if you need to know "what was this model trained on"
  raw/                          .csv files land here (gitignored; fetch_datasets.py
                                 or you, manually for Kaggle downloads, populate it)
    kaggle/                       Your own Kaggle-downloaded CSVs go here

alembic/
  env.py                      Points at app.core.config.settings.DATABASE_URL,
                               imports all models for autogenerate support
  versions/
    dd0723c3586c_initial_schema.py                          All 41 tables
    c7bd488f4839_add_account_lockout_fields_to_users.py     failed_login_attempts, locked_until
    873fb9353f04_add_api_key_service_user_columns.py        service_user_id, created_by_user_id

tests/                        62 tests, all passing -- see "Running tests" below
  conftest.py                  Fresh SQLite DB + rate-limiter reset per test
  fixtures/                     Sample phishing and benign .eml files
  test_auth.py, test_account_security.py, test_api_keys_and_roles.py,
  test_ingestion.py, test_enrichment_and_reporting.py, test_msg_parser.py,
  test_ml_text_model.py          One file per feature area, matching app/ layout

docs/
  architecture.md             System design, data flow, extension points
  security.md                  Platform security posture (auth, rate limiting, lockout)
  threat_model.md               What each detection signal does/doesn't establish
  forensic_workflow.md           Chain-of-custody guarantees
  sih_pitch.md                    Demo script + judging-criteria alignment
```

## Forensic Intelligence: attribution without overclaiming

Beyond "is this malicious," every case also answers "where did it come
from, and how sure are we." This is deliberately kept separate from the
risk score -- confidence in an origin/geolocation claim is a different
concept from how dangerous the email is.

- **Earliest Reliable External Origin** (`app/services/origin_resolution.py`):
  walks the Received-header chain from the recipient outward, skipping
  private/internal hops, and picks the deepest well-formed public IP
  as the origin -- with a stated confidence and a plain-English
  explanation of the reasoning. Returns "could not be determined"
  rather than guessing when the chain doesn't support a conclusion.
- **IP intelligence** (`app/services/ip_intelligence.py`): reverse DNS
  (real PTR lookups) and a hosting/datacenter classification heuristic
  based on ASN organization name matching -- honestly labeled as a
  heuristic, with VPN/Tor fields left `null` (unknown) rather than
  guessed, since no real-time VPN/Tor data source is wired in.
- **DNS forensics** (`app/services/dns_forensics.py`): real A/MX/NS/TXT
  queries for every domain IOC, recorded append-only whether they
  succeed or fail.
- **Domain WHOIS** (`app/services/whois_lookup.py`): on-demand (not
  automatic at ingestion time -- raw WHOIS is slow/unreliable across
  networks) via `GET /cases/{id}/domain-intelligence/{domain}`.
- **Blockchain evidence-integrity ledger** (`app/services/blockchain_ledger.py`):
  a genuine cryptographic hash chain (not a distributed/public
  blockchain) anchoring every case's evidence SHA-256 -- each entry
  commits to the previous entry's hash, so tampering anywhere in the
  history is detectable via `GET /organizations/blockchain-verify`.

All of this is additive to the existing pipeline (`ingest_email_and_create_case()`
is unchanged in its outward behavior/contract) and every new lookup
degrades gracefully -- a DNS timeout, missing ASN data, or unreachable
WHOIS server never fails the case, only marks that specific piece of
intelligence "unavailable."

## Presentation prompt

`GAMMA_PRESENTATION_PROMPT.txt` in the project root is a ready-to-paste
prompt for Gamma.app (or similar AI slide generators) that produces a
10-slide pitch deck accurately describing what's built, what's
roadmap, and why.

## Running tests

```bash
pip install -e ".[dev]"
pytest -v
```

Tests run against a throwaway SQLite database and local-filesystem
evidence directory -- no external services, no real training data,
required. 62 tests, all passing as of this writing.

## Honesty notes (things intentionally *not* faked)

- The text-content model is trained on real data, but that data is
  **general spam/phishing/legitimate email corpora**, not necessarily
  representative of every phishing style your organization will see --
  see `docs/threat_model.md`.
- The structural model's training data IS synthetic (no real dataset
  pairs SPF/DKIM outcomes with ground truth) -- its `model_version`
  string says so, and every finding it produces states this caveat.
- DKIM is reported from the `Authentication-Results` header when
  present; full cryptographic re-verification is not implemented.
- External threat-intel providers only run if you configure their API
  keys; the offline heuristic provider's observations are always
  labeled `is_synthetic_demo_data=True`.
- Campaign correlation uses exact IOC-value matching only, no fuzzy
  content-similarity clustering yet.
- Forward-to-mailbox ingestion (mode 3 above) does not exist yet.

## What's still open

See `NEXT_STEPS.md` for the full list with rationale. Headline items:
IMAP mailbox-forwarding ingestion, fuzzy campaign correlation, richer
graph edge types, and (once you've trained it) validating the
text-content model against your own organization's real historical
phishing reports rather than only the general public corpora it ships
trained on by default.
