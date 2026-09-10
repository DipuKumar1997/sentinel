# SentinelMail AI

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**
Prototype for Smart India Hackathon 2026 — Problem Statement **SIH26106**.

> Status: **Final application** — a complete, tested, end-to-end platform:
> registration → authenticated email submission (`.eml`/`.msg`) →
> forensic parsing → threat-intel enrichment → deterministic + trained-ML
> analysis → explainable risk scoring → campaign correlation → HTML/PDF
> reporting → a browser dashboard to do all of the above without curl.
> See `CHANGELOG.md` for the full build history and `NEXT_STEPS.md` for
> what's still genuinely open (mainly: swapping the synthetic-data
> trained model for one fit on real labeled traffic).

## What this is

A reporter (an employee at a registered organization) logs in and submits
a suspicious `.eml` file. The platform:

1. Verifies the reporter's identity via their authenticated session —
   **never** by trusting anything inside the submitted email itself.
2. Preserves the raw bytes as immutable, hashed evidence (chain of
   custody) before any parsing is attempted.
3. Parses the email (RFC 5322 / MIME, or Outlook `.msg`) into headers,
   the reconstructed `Received:` hop chain, sender identity claims, body
   text/HTML, and attachments.
4. Extracts IOCs (domains, IPs, URLs, attachment hashes), evaluates
   SPF/DKIM/DMARC evidence, and enriches domains/IPs against threat
   intelligence (an always-on offline heuristic provider, plus optional
   VirusTotal/AbuseIPDB/IPinfo lookups if you configure API keys).
5. Runs independent analysis engines — rule-based header/URL forensics,
   the threat-intel engine, and a trained (if a bit synthetically
   trained) ML classifier — each emitting explainable findings with a
   severity and confidence.
6. Fuses those findings into a single 0–100 risk score with a
   human-readable rationale — deterministic and auditable, not a
   black-box verdict.
7. Automatically correlates the case against other recent cases in the
   same organization sharing an indicator of compromise, grouping them
   into a `Campaign` when found.
8. Returns a `Case` the reporter's organization can review, browse in
   the built-in dashboard (`/ui/`), and export as an HTML or native PDF
   forensic report.

## Quickstart (Docker)

```bash
cp .env.example .env
# edit SECRET_KEY at minimum before anything beyond local testing
docker compose up --build
```

The API will be available at `http://localhost:8000`, with interactive
docs at `http://localhost:8000/docs` and a browser dashboard at
`http://localhost:8000/ui/`. Migrations and role/permission seeding run
automatically on container start.

## Quickstart (local Python, no Docker)

Requires Python 3.12+ and a running PostgreSQL instance.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # point DATABASE_URL at your local Postgres
alembic upgrade head
python -m app.db.seed
uvicorn app.main:app --reload
```

## Running the test suite

Tests run against a throwaway SQLite database and local-filesystem
evidence directory — no external services required.

```bash
pip install -e ".[dev]"
pytest -v
```

## Re-training the ML classifier

A trained model artifact (`app/ml_models/phishing_classifier.joblib`) is
already included, but you can regenerate it (e.g. after editing the
feature set or the synthetic data generator):

```bash
python -m scripts.train_model
```

See `docs/threat_model.md` for why this model's training data is
synthetic and what that does/doesn't mean for the risk score.

## Using the dashboard

Once the API is running, open `http://localhost:8000/ui/` in a browser:
register (your organization is created automatically from your email's
domain), verify your email using the token shown after registration,
log in, then drag a `.eml` or `.msg` file onto the upload area. Cases,
their risk scores/findings, HTML/PDF reports, and any auto-detected
campaigns are all browsable from there.

## Example walkthrough (curl)

```bash
# 1. Register (organization is derived from your email's domain)
curl -X POST localhost:8000/api/v1/auth/register -H "Content-Type: application/json" -d '{
  "full_name": "Alice Analyst",
  "email": "alice@acmecorp.com",
  "password": "SuperSecret123!",
  "organization_name": "Acme Corp"
}'
# -> response includes a verification_token (emailed in production)

curl -X POST localhost:8000/api/v1/auth/verify-email -H "Content-Type: application/json" \
  -d '{"token": "<paste verification_token here>"}'

curl -X POST localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d '{
  "email": "alice@acmecorp.com", "password": "SuperSecret123!"
}'
# -> {"access_token": "...", "refresh_token": "..."}

# 2. Submit a suspicious email
curl -X POST localhost:8000/api/v1/ingestion/eml \
  -H "Authorization: Bearer <access_token>" \
  -F "file=@suspicious_message.eml"

# 3. Review the case
curl localhost:8000/api/v1/cases/<case_id>/risk-score -H "Authorization: Bearer <access_token>"
curl localhost:8000/api/v1/cases/<case_id>/findings -H "Authorization: Bearer <access_token>"
```

## Project layout

```
app/
  core/config.py, limiter.py  # env-driven settings + shared rate-limiter instance
  db/                      # engine/session, declarative base, seed script
  models/                  # 41 SQLAlchemy ORM models across 8 modules
  ml_models/               # trained model artifact (phishing_classifier.joblib)
  schemas/                 # Pydantic request/response models
  security/                # password hashing, JWT, RBAC, auth dependency
  services/
    eml_parser.py           # RFC 5322 / MIME parsing
    msg_parser.py            # Outlook .msg parsing -> same ParsedEmail shape
    auth_results.py          # SPF/DKIM/DMARC header parsing + live DNS check
    ioc_extraction.py        # domain/IP/URL/attachment-hash extraction
    ml_features.py            # shared feature extraction (training + inference)
    ml_scoring.py              # trained-model inference w/ heuristic fallback
    threat_intel.py             # offline heuristic + optional VT/AbuseIPDB/IPinfo
    campaign_correlation.py      # shared-IOC campaign + graph building
    evidence_storage.py           # content-addressed evidence storage
    report_generator.py            # HTML + native PDF report rendering
    analysis_engines/                # independent, pluggable analysis engines
    risk_fusion.py                    # explainable score fusion
    auth_service.py                    # register/login/verify/refresh/lockout
    ingestion.py                        # orchestrates the full pipeline end to end
    audit.py                             # append-only audit log writer
  api/routers/    # auth, cases, ingestion, reports, campaigns, health
  main.py         # FastAPI app assembly + rate limiter + /ui static mount
frontend/
  index.html      # single-page dashboard (login, upload, cases, campaigns, reports)
scripts/
  train_model.py  # generates synthetic labeled data, trains + saves the classifier
alembic/          # migration environment + schema migrations
tests/            # pytest suite (23 tests, all passing)
docs/             # architecture, security, threat model, forensic workflow, pitch
```

## Documentation

- `docs/architecture.md` — system design, data flow, extension points
- `docs/security.md` — threat model for the platform itself, RBAC, secrets handling
- `docs/threat_model.md` — the *email* threat model this platform detects against
- `docs/forensic_workflow.md` — how evidence integrity/chain-of-custody is maintained
- `docs/sih_pitch.md` — problem statement framing and demo script

## Honesty notes (things intentionally *not* faked)

- DKIM is reported from the `Authentication-Results` header when present;
  full cryptographic re-verification of the DKIM signature against DNS-published
  keys is not implemented (see `docs/threat_model.md`).
- SPF/DMARC live checks report policy *presence*, not full RFC 7208
  alignment evaluation against the connecting IP.
- The trained ML classifier (`phishing_classifier_lr`) is fit on
  **synthetically generated** feature combinations, not real-world
  labeled email traffic — its `model_version` string is suffixed
  `-synthetic` for exactly this reason, and every model-based finding
  says so in its description. See `scripts/train_model.py` and
  `docs/threat_model.md`.
- External threat-intel providers (VirusTotal/AbuseIPDB/IPinfo) are only
  called if you configure their API keys; without keys, the platform
  runs on its offline heuristic provider alone and labels every such
  observation `is_synthetic_demo_data=True` — nothing is presented as a
  real third-party verdict unless it is one.
- Campaign correlation uses exact IOC-value matching only; no fuzzy
  content-similarity clustering yet (see `NEXT_STEPS.md`).
