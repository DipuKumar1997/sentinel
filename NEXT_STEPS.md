# Next Steps

## Forward-to-mailbox ingestion (the third intake mode)
The `Mailbox` database table already exists (`app/models/case.py`) but
there is no IMAP-polling worker. To implement:
1. Add IMAP config fields to `Mailbox` (host, port, username, an
   *encrypted* password -- use `cryptography.fernet.Fernet` with a key
   derived from `SECRET_KEY`, never store plaintext).
2. Write `app/services/mailbox_polling.py` using `imaplib` to fetch
   unseen messages and call `ingestion.ingest_email_and_create_case()`
   with `reporter_user_id` = a dedicated service-account user per
   mailbox (same pattern as `api_key_service.py`'s service accounts).
3. Add a Celery beat schedule (`app/workers/celery_app.py`) to poll
   every active mailbox on an interval, plus a manual
   `POST /mailboxes/{id}/poll-now` endpoint for testing.

## Validate the text-content model against real organizational data
`scripts/train_text_model.py` trains on general public corpora (see
`data/README.md`). Once you have real historical phishing reports from
your own organization (with the reporter's identity stripped/hashed for
privacy), adding them to `data/raw/kaggle/` (or a new subdirectory --
the loader doesn't care about the folder name) and retraining will
likely outperform the general-corpus-only model for your specific
threat landscape.

## Fuzzy campaign correlation
`app/services/campaign_correlation.py` currently clusters only on exact
IOC-value matches. Content-similarity clustering (e.g. body-text
embedding distance) would catch campaigns that rotate infrastructure
per message but reuse the same template/wording.

## Richer graph relationships
`GraphRelationship` currently only has `case -> ioc` edges. Adding
`domain -> ip` (`resolves_to`, derivable from `ReceivedHop` data already
captured) and `case -> case` (`same_campaign`) edges would make the
graph more useful for a future pivot-style investigation UI.

## Remaining hardening backlog
- "Log out all devices" (bulk refresh-token revocation) -- only
  single-token revocation via rotation exists today.
- CORS defaults to `allow_origins=["*"]` under `DEBUG=true`; restrict
  before any non-local deployment.
- No 2FA/MFA.

## How to resume work
1. `pip install -e ".[dev]"`, `pytest -v` to confirm all 33 existing
   tests still pass before changing anything.
2. New analysis engines follow the same `Finding` dataclass contract
   (`app/services/analysis_engines/*.py`) and get appended to the list
   built in `app/services/ingestion.py::ingest_email_and_create_case()`.
3. New tables: add the model, import it in `app/models/__init__.py`,
   then hand-write the migration (see the pattern in
   `alembic/versions/c7bd488f4839_*.py` and `873fb9353f04_*.py`) rather
   than trusting `alembic revision --autogenerate` against a SQLite
   shadow DB, which reproduces spurious UUID/NUMERIC diff noise across
   every existing column every time.
