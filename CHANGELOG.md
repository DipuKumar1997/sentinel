# Changelog

## Real data + dual models + API-key ingestion + admin tooling — 2026-09-06

### Added
- **Real-data text-content ML model**: `scripts/fetch_datasets.py`
  downloads ~82,000 genuinely labeled emails across 6 well-known
  academic corpora (Enron, Nazario phishing corpus, Nigerian-fraud/419
  corpus, SpamAssassin, Ling-Spam, CEAS 2008) via GitHub;
  `app/services/dataset_loader.py` harmonizes any CSV (including
  user-provided Kaggle downloads dropped into `data/raw/kaggle/`) into
  one schema; `scripts/train_text_model.py` trains a TF-IDF + Logistic
  Regression classifier and prints a full dataset + accuracy report.
  Smoke-tested end-to-end (97% held-out accuracy on a 4,000-row
  subsample) but the full run is left to be executed by the user on
  their own machine.
- **Two independent ML models**, not one: split the previous single
  `ml_scoring.py` into `ml_scoring_structural.py` (existing
  synthetic-data model) and `ml_scoring_text.py` (new real-data model),
  sharing a common `ModelOutput` type (`ml_common.py`). Both feed risk
  fusion as separate, separately-labeled findings
  (`ml_model_structural` / `ml_model_text`); either can be present or
  absent independently with no crash.
- **API-key ingestion** (the second of three intake modes):
  `app/services/api_key_service.py` + `POST/GET /api-keys`,
  `DELETE /api-keys/{id}` (org_admin+ only). Each key is backed by a
  dedicated, non-loginable service-account user so API-key-created
  cases remain attributable. `app/security/deps.py::get_current_actor`
  accepts either a JWT or an `X-API-Key` header on the ingestion
  endpoints specifically.
- **Fixed a real pre-existing gap**: registration never had a path to
  create an `org_admin` (everyone defaulted to `employee`), which would
  have made the new API-key endpoints permanently unreachable. Now the
  first person to register for a brand-new organization becomes its
  admin automatically; joining an already-existing org still gives the
  baseline `employee` role.
- **User role management**: `GET /users`, `PATCH /users/{id}/role`
  (org_admin+, org-scoped) so admins can promote colleagues.
- **pgAdmin** added to `docker-compose.yml` (port 5050) for visual
  Postgres access.
- Hand-written migration `873fb9353f04` for the two new `api_keys`
  columns (`service_user_id`, `created_by_user_id`).
- `data/README.md`: the definitive, single-file record of exactly which
  datasets train the text model, with row counts and provenance.
- 10 new tests (`tests/test_api_keys_and_roles.py`,
  `tests/test_ml_text_model.py`) covering API-key creation/use/
  revocation, cross-tenant isolation for API-key-created cases, the
  new org_admin auto-promotion, role updates, and both the
  text-model-absent and text-model-present (mocked) code paths.
  **33/33 tests passing.**
- Comprehensive README rewrite: full low-level architecture walkthrough,
  a table of every endpoint and exactly what credential it requires,
  the three intake modes and their status, and a complete file
  manifest.

### Fixed
- `app/db/seed.py`'s RBAC seeding previously assigned
  `role.permissions = [...]` directly, which triggered an async
  lazy-load (`MissingGreenlet`) under asyncpg. Rewritten to write
  directly to the `role_permissions` join table via explicit
  `delete()`/`insert()` statements, sidestepping the ORM relationship
  entirely rather than working around one instance of the problem.
- A missing `app.include_router(user_management.router, ...)` call
  (the module was imported but never registered) caught by the test
  suite before it shipped -- `GET /users` was 404ing.

### Known limitations carried forward
- Forward-to-mailbox ingestion (intake mode 3) still not implemented.
- The text-content model, once trained, reflects general public
  phishing/spam corpora, not your organization's specific threat
  landscape -- see NEXT_STEPS.md for how to fold in real historical
  data from your own organization.
- Campaign correlation remains exact-IOC-match only.

## Final application — 2026-09-05

Hardening, a real trained model, native PDF export, and a browser
dashboard — completing the platform end to end.

### Added
- **Trained ML classifier**: `scripts/train_model.py` generates a
  synthetic labeled dataset and fits a real scikit-learn
  `LogisticRegression` (`phishing_classifier_lr`, 98% held-out accuracy
  on the synthetic distribution), replacing the pure hand-weighted
  scaffold as the default scorer; `app/services/ml_features.py` is the
  single shared feature-extraction path used by both training and
  inference so the two never drift apart. Falls back to the original
  heuristic scaffold automatically if the model artifact is missing.
  Honestly labeled throughout (`-synthetic` version suffix, finding
  descriptions state the caveat) — see docs/threat_model.md.
- **Rate limiting**: `slowapi` now actually enforces 10 requests/minute
  on `/auth/login` and `/auth/register` (shared `Limiter` instance in
  `app/core/limiter.py`), returning 429 once exceeded.
- **Account lockout**: new `failed_login_attempts`/`locked_until`
  columns on `User` (hand-written migration
  `c7bd488f4839_add_account_lockout_fields_to_users.py`); 5 failed
  logins lock the account for 15 minutes (423 response), counter resets
  on any successful login.
- **Native PDF report export**: `app/services/report_generator.py` now
  renders either HTML or a real PDF (via `fpdf2`, pure-Python, no system
  rendering dependency) from the same gathered report data;
  `GET /cases/{id}/report?format=pdf|html`.
- **Browser dashboard**: `frontend/index.html`, a single-page vanilla-JS
  app (register/verify/login, drag-and-drop `.eml`/`.msg` upload, case
  list, risk-score + findings detail view, HTML/PDF report links,
  campaigns list) served at `/ui/` via FastAPI `StaticFiles` — the
  platform is now usable end to end without curl or `/docs`.
- 6 new tests (`tests/test_account_security.py` + 1 PDF-format test in
  `tests/test_enrichment_and_reporting.py`) covering lockout-after-5-
  failures, counter-reset-on-success, rate-limit-429, and PDF magic-byte
  validation. **23/23 tests passing.**

### Fixed
- A `fpdf2` API-version bug: `multi_cell()`'s default cursor behavior
  leaves it at the *right* margin (not reset to the left) after
  rendering, which broke every `kv_row()` call after the first with
  "Not enough horizontal space to render a single character." Fixed by
  explicitly passing `new_x="LMARGIN", new_y="NEXT"` at every call site
  in `report_generator.py`.
- A second autogenerated-migration attempt (for the lockout columns)
  produced the same SQLite-vs-Postgres UUID/NUMERIC diff noise seen in
  Checkpoint 1; discarded in favor of a small, hand-written, reviewed
  migration containing only the two actually-changed columns.

### Verified locally (this round)
- Full walkthrough script: dashboard reachable at `/ui/` → register →
  verify → login → submit phishing `.eml` → 98/100 malicious, 14
  findings across all 4 engines (`header_forensics`,
  `url_domain_analysis`, `threat_intelligence`, `ml_model`) → HTML and
  PDF reports both generate correctly → second identical submission
  auto-creates a campaign → wrong password correctly rejected.
- `python -m scripts.train_model` reproducibly regenerates the model
  artifact with a printed classification report.

### Known limitations carried forward
- The trained model's training data is synthetic, not real-world
  traffic (see docs/threat_model.md).
- Campaign correlation is exact-IOC-match only, no fuzzy similarity.
- No "log out all devices" / per-session token listing.
- CORS still defaults permissive under `DEBUG=true` for local dev.

## Checkpoint 2 — 2026-09-05

Phases 6–10 implemented on top of Checkpoint 1's vertical slice.

### Added
- **Phase 6 (threat intel):** `app/services/threat_intel.py` -- an
  always-available offline heuristic provider plus optional VirusTotal/
  AbuseIPDB/IPinfo HTTP clients (only called when their API key is
  configured); a new `threat_intelligence` analysis engine
  (`app/services/analysis_engines/threat_intel_engine.py`) turns
  observations into findings; every observation persists as an
  append-only `ThreatIntelligenceObservation` row.
- **Phase 7 (campaign/graph correlation):** `app/services/campaign_correlation.py`
  detects shared-IOC clusters across an organization's recent cases and
  groups them into a `Campaign`/`CampaignMembership`, and populates
  `GraphEntity`/`GraphRelationship` (case -> IOC edges). New endpoints:
  `GET /campaigns`, `GET /campaigns/{id}/cases`.
- **Phase 8 (ML scoring scaffold):** `app/services/ml_scoring.py` --
  `heuristic_model_v0`, an explicitly-labeled, hand-weighted (not
  trained) scoring function proving out the `ModelPrediction` ->
  risk-fusion data path end-to-end.
- **Phase 9 (reporting):** `app/services/report_generator.py` renders a
  self-contained HTML forensic report (evidence hash, findings, model
  predictions, case status history) via Jinja2; `GET /cases/{id}/report`
  serves it and persists a `Report` + evidence record.
- **Phase 10 (Outlook .msg support):** `app/services/msg_parser.py`
  converts `.msg` (via `extract-msg`) into the same `ParsedEmail` shape
  the `.eml` parser produces, so the rest of the pipeline is unchanged;
  new `POST /ingestion/msg` endpoint.
- `app/services/ingestion.py` refactored into a single format-agnostic
  `ingest_email_and_create_case()` (with a backward-compatible
  `ingest_eml_and_create_case()` alias) that now also runs threat-intel
  enrichment, ML scoring, and campaign/graph correlation as part of the
  same per-case transaction.
- 10 new tests (`tests/test_msg_parser.py`,
  `tests/test_enrichment_and_reporting.py`) covering .msg parsing
  (mocked backend), threat-intel + ML findings appearing in the API
  response, report generation/auth, campaign creation across two
  matching cases, and campaign tenant isolation. **19/19 tests passing
  total.**

### Verified locally (this checkpoint)
- Manual end-to-end run: phishing sample now scores 98/100 with 14
  findings across 4 engines (header_forensics, url_domain_analysis,
  threat_intelligence, ml_model); a second identical submission
  correctly triggers automatic campaign creation.
- `alembic check` confirms no real schema drift since Checkpoint 1 (the
  UUID/NUMERIC diff it reports is a known SQLite-vs-Postgres dialect
  comparison artifact, not an actual model change -- no new migration
  was needed for this checkpoint).

### Known limitations carried forward
- `heuristic_model_v0` is explicitly not a trained classifier (see
  docs/threat_model.md and NEXT_STEPS.md).
- Report export is HTML only; PDF rendering deferred.
- Campaign correlation uses exact IOC-value matching only, no fuzzy
  content similarity yet.
- No frontend/dashboard.

## Checkpoint 1 — 2026-09-05

Initial working vertical slice.

### Added
- Project skeleton: `pyproject.toml`, Docker Compose (api/worker/db/redis),
  `.env.example`, `Dockerfile`.
- 41 SQLAlchemy ORM models across organizations, RBAC, users, cases,
  evidence, email/headers/hops/auth-results, IOCs/attachments/threat-intel,
  analysis runs/findings/risk-scores, campaigns/graph, alerts/reports/audit.
- Alembic async migration environment + initial schema migration
  (`alembic/versions/dd0723c3586c_initial_schema.py`), verified to apply
  cleanly to a fresh database.
- Security layer: Argon2id password hashing, JWT access tokens, rotating
  opaque refresh tokens, role-hierarchy RBAC dependencies.
- Forensic core:
  - `app/services/eml_parser.py` — RFC 5322/MIME parsing, Received-hop
    chain reconstruction with per-hop confidence scoring.
  - `app/services/auth_results.py` — Authentication-Results header
    parsing plus optional live SPF/DMARC DNS lookups.
  - `app/services/ioc_extraction.py` — domain/IP/URL/attachment-hash
    extraction and normalization.
  - `app/services/evidence_storage.py` — content-addressed, read-only,
    path-traversal-guarded evidence storage.
- Two deterministic analysis engines (`header_forensics`,
  `url_domain_analysis`) and an explainable risk-fusion engine
  (`app/services/risk_fusion.py`).
- Auth service enforcing domain-based org matching and reporter/sender
  identity separation (`app/services/auth_service.py`).
- End-to-end ingestion orchestration (`app/services/ingestion.py`) tying
  all of the above together inside a single DB transaction per case.
- FastAPI routers: `auth` (register/verify/login/refresh/me), `cases`
  (list/get/risk-score/findings), `ingestion` (.eml upload), `health`.
- `app/db/seed.py` — idempotent RBAC role/permission seeding.
- Test suite: 9 tests covering auth flow, duplicate registration, wrong
  password, unauthenticated access, non-.eml rejection, empty-file
  rejection, phishing-email-flagged-malicious, benign-email-scores-low,
  and cross-tenant case isolation. **All passing.**
- Documentation: `README.md`, `docs/architecture.md`,
  `docs/security.md`, `docs/threat_model.md`,
  `docs/forensic_workflow.md`, `docs/sih_pitch.md`.

### Verified locally (this checkpoint)
- All 41 models import and generate valid DDL (SQLite smoke test).
- Alembic migration generated and applied cleanly to a fresh database.
- Full end-to-end flow exercised manually and via pytest: register →
  verify → login → submit phishing .eml → risk score 78/100
  (malicious) with 11 explainable findings → submit benign .eml → risk
  score 0/100 (benign) → cross-tenant case access correctly returns 404.

### Known limitations (see docs/threat_model.md and NEXT_STEPS.md)
- No threat-intel provider calls yet (VirusTotal/AbuseIPDB/IPinfo).
- No campaign/graph correlation yet.
- No ML models yet (all findings are deterministic/rule-based).
- No PDF/report export yet.
- `.eml` only; no Outlook `.msg` support yet.
- Rate limiting dependency installed but not yet applied to routes.
