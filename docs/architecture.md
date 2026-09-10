# Architecture — SentinelMail AI (Checkpoint 1)

## 1. Goals of this checkpoint

Build a real, runnable, tested vertical slice of the platform described
in the SIH26106 master prompt: identity-verified case intake through to
an explainable risk score. Every later phase (threat-intel enrichment,
campaign/graph correlation, ML models, reporting, dashboards) hooks into
data structures that already exist in this checkpoint's schema, so later
work is additive rather than a rewrite.

## 2. High-level data flow

```
┌──────────────┐     ┌───────────────┐     ┌────────────────────┐
│  Reporter    │────▶│  Auth/RBAC     │────▶│  Ingestion router   │
│  (browser/   │     │  (JWT session) │     │  POST /ingestion/eml│
│   API client)│     └───────────────┘     └──────────┬──────────┘
└──────────────┘                                       │
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 1. Hash + store raw bytes  │
                                         │    (evidence_objects,      │
                                         │     evidence_hashes)       │
                                         └──────────────┬─────────────┘
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 2. Parse RFC5322/MIME      │
                                         │    (email_messages,        │
                                         │     email_headers,         │
                                         │     received_hops,         │
                                         │     sender_identities,     │
                                         │     attachments)            │
                                         └──────────────┬─────────────┘
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 3. SPF/DKIM/DMARC evidence  │
                                         │    (authentication_results) │
                                         └──────────────┬─────────────┘
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 4. IOC extraction           │
                                         │    (domains, ips, urls,     │
                                         │     ioc_records)            │
                                         └──────────────┬─────────────┘
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 5. Analysis engines         │
                                         │    (header_forensics,       │
                                         │     url_domain_analysis)    │
                                         │    -> analysis_findings     │
                                         └──────────────┬─────────────┘
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ 6. Risk fusion               │
                                         │    -> risk_scores            │
                                         └──────────────┬─────────────┘
                                                         ▼
                                                    Case updated,
                                                    ready for analyst
                                                    review / escalation
```

All of the above happens synchronously inside `app/services/ingestion.py`
for this checkpoint, inside a single DB transaction per case, so a
submitted email either produces a fully-analyzed case or an explicit
error — there is no partially-analyzed state visible to the API. As
volume grows, this pipeline is designed to move behind the already-scaffolded
Celery worker (`app/workers/`) without changing its internal structure:
each step is already a plain function taking/returning plain dataclasses,
so wrapping it in a task is mechanical.

## 3. Why identity separation matters (and how it's enforced)

The single most important invariant in this system: **the reporter's
identity and the suspected sender's identity are never the same table,
concept, or code path.**

- `User` = an authenticated platform account, verified via email
  ownership at registration and a password at login. This is who the API
  believes is making the request (`get_current_user`, JWT `sub` claim).
- `SenderIdentity` = an unverified *claim* extracted from the `From`
  header of the submitted email. It is explicitly documented in code as
  untrusted (see the docstring in `app/models/email.py`).

`ingest_eml_and_create_case()` takes `reporter_user_id` as an explicit
parameter sourced only from `get_current_user`, never from anything
parsed out of the uploaded file. This is checked by
`test_tenant_isolation_between_organizations` and enforced structurally
by `Case.organization_id` scoping every read in `app/api/routers/cases.py`.

## 4. Analysis engine design

Each engine in `app/services/analysis_engines/` is a pure function:
`(parsed evidence) -> list[Finding]`. This makes them:

- **Independently testable** — no shared mutable state, no DB access.
- **Explainable** — every `Finding` carries `engine`, `code`, `severity`,
  `confidence`, and a human-readable `description`.
- **Additive** — a new engine (e.g. an ML-based BEC classifier) is just
  another function appended to the list in `ingestion.py`; it does not
  need to know about the others.

`app/services/risk_fusion.py` is deliberately a simple, auditable
weighted-sum-with-diminishing-returns model rather than a black-box
ensemble, per the product requirement that a human analyst can always
see *why* a case scored the way it did. Machine-learned model output
(see the `ModelPrediction` table) is designed to enter this same fusion
step as additional findings once models are trained/integrated — not as
a separate, competing verdict.

## 5. Database design notes

41 tables across 8 model modules (`organization`, `rbac`, `user`, `case`,
`evidence`, `email`, `ioc`, `analysis`, `campaign`, `alert`). Key design
choices:

- **UUID primary keys everywhere** — safe to expose in URLs, no
  sequential-ID enumeration risk, and trivially mergeable across future
  sharding if needed.
- **Append-only tables** for anything forensic or audit-relevant
  (`audit_logs`, `case_status_history`, `threat_intelligence_observations`,
  `email_headers`) — these are never updated in place, only inserted,
  so history is always reconstructable.
- **Evidence is content-addressed** (`EvidenceHash`, filename = sha256
  digest) so tampering is structurally detectable and identical evidence
  across cases is naturally deduplicated on disk.
- **IOC records are a normalized junction** between a `Case` and a
  concrete `Domain`/`IPAddress`/`URLRecord`/`Attachment` row, enabling
  cross-case correlation queries (e.g. "which other cases touched this
  domain?") without duplicating the IOC's own metadata per-case.

See `alembic/versions/` for the generated DDL, or run
`alembic upgrade head` against Postgres to materialize the schema.

## 6. Security posture in this checkpoint

- Passwords hashed with Argon2id (`app/security/passwords.py`).
- Access tokens are short-lived JWTs; refresh tokens are opaque random
  strings, stored server-side only as a SHA-256 hash, and rotated
  (single-use) on every refresh (`app/security/tokens.py`,
  `app/services/auth_service.py`).
- RBAC via a role hierarchy plus a normalized permissions table for
  future custom roles (`app/models/rbac.py`, `app/security/rbac.py`).
- Every case-scoped read filters by `organization_id` against the
  *authenticated* user's own organization — see `app/api/routers/cases.py`.
- Evidence storage guards against path traversal
  (`app/services/evidence_storage.py::_safe_case_dir`).
- A global exception handler in `app/main.py` prevents stack traces from
  ever reaching a client response.

See `docs/security.md` for the full threat model of the platform itself.

## 7. What's explicitly deferred (see NEXT_STEPS.md for detail)

- Threat-intel provider calls (VirusTotal/AbuseIPDB/IPinfo) — config
  keys exist, HTTP client code does not yet.
- Campaign/graph correlation across cases.
- ML-based classifiers (BEC detection, phishing NLP models).
- PDF/HTML report generation and Jinja2 report templates.
- Outlook `.msg` file parsing (currently `.eml` only).
- Rate limiting middleware wiring (dependency installed, not yet applied
  to routes).
- Frontend/dashboard (this checkpoint is API-only).
