# Next Steps

This is a complete, tested, end-to-end application (see CHANGELOG.md for
the full build history: 23/23 tests passing, dashboard + API + trained
model + PDF export + campaign correlation all working together). What
follows is genuinely open work, not gaps in disguise.

## Replace synthetic training data with real labeled traffic
- `scripts/train_model.py` currently trains `phishing_classifier_lr` on
  a **synthetically generated** dataset (no real-world labeled corpus
  was available in this environment) -- see docs/threat_model.md.
  Swapping in real labeled email data requires no pipeline or schema
  changes: point `generate_dataset()` (or replace it entirely) at real
  data and re-run the script; `app/services/ml_scoring.py` picks up the
  new `phishing_classifier.joblib` artifact automatically.

## Fuzzy campaign correlation
- `app/services/campaign_correlation.py` currently clusters only on
  exact IOC-value matches. Content-similarity clustering (e.g. body-text
  embedding distance) would catch campaigns that rotate infrastructure
  per message but reuse the same template/wording.

## Richer graph relationships
- `GraphRelationship` currently only has `case -> ioc` (`case_has_ioc`)
  edges. Adding `domain -> ip` (`resolves_to`) edges (the data is
  already available per-hop in `ReceivedHop`) and `case -> case`
  (`same_campaign`) edges would make the graph more useful for
  pivot-style investigation via a future graph-visualization endpoint.

## Remaining hardening backlog
- "Log out all devices" (bulk refresh-token revocation by user) --
  currently only single-token revocation via rotation exists.
- CORS defaults to `allow_origins=["*"]` under `DEBUG=true`; restrict to
  real frontend origin(s) before any non-local deployment.
- No 2FA/MFA.

## Frontend polish
- `frontend/index.html` is a functional single-page dashboard, not a
  polished production UI (no framework, no build step, no routing
  library). It's a real, working consumer of every API endpoint though
  -- a good base for a React/Vue rewrite if the project grows.

## How to resume work
1. `pip install -e ".[dev]"`, `pytest -v` to confirm all 23 existing
   tests still pass before changing anything.
2. New analysis engines follow the same `Finding` dataclass contract
   (`app/services/analysis_engines/*.py`) and get appended to the list
   built in `app/services/ingestion.py::ingest_email_and_create_case()`.
3. New tables: add the model, import it in `app/models/__init__.py`,
   then either autogenerate against a fresh SQLite shadow DB (see
   docs/architecture.md) and manually prune the spurious UUID/NUMERIC
   diff noise, or hand-write the migration as done for the account
   lockout columns (`alembic/versions/c7bd488f4839_*.py`) -- the latter
   is cleaner for small, well-understood changes.
