# Security — SentinelMail AI

This document covers the security posture of the **platform itself**
(how we protect it from being compromised or misused). For the security
of the *email threat detection domain* (what phishing/BEC/malware
techniques we detect against), see `docs/threat_model.md`.

## Authentication & session management

- **Password storage**: Argon2id via `argon2-cffi`, a memory-hard KDF
  resistant to GPU/ASIC cracking, in preference to bcrypt/PBKDF2.
- **Access tokens**: short-lived (30 min default) signed JWTs. The
  signing key (`SECRET_KEY`) must be rotated to a strong random value
  (`openssl rand -hex 32`) before any non-local deployment — the
  `.env.example` default is explicitly marked dev-only.
- **Refresh tokens**: opaque random 48-byte tokens, never JWTs. Only a
  SHA-256 hash is persisted server-side, so a stolen database dump alone
  cannot be replayed as a valid refresh token without also compromising
  a live client session. Refresh is single-use/rotating: using a refresh
  token immediately revokes it and issues a new one, limiting the
  blast radius of a leaked-but-unused token.
- **Email verification**: registration does not activate an account;
  a random 32-byte token (SHA-256-hashed at rest, 24h TTL, single-use)
  must be redeemed first.

## Authorization

- Role hierarchy (`app/security/rbac.py`): `employee` < `security_analyst`
  < `investigator` < `soc_admin` < `org_admin` < `platform_admin`.
  `require_min_role()` and `require_roles()` are FastAPI dependencies
  usable on any route.
- A normalized `roles`/`permissions`/`role_permissions` schema exists
  alongside the coarse role enum so fine-grained, per-organization custom
  permissions can be layered on without a schema migration later.
- **Tenant isolation**: every case-scoped query filters explicitly by
  `Case.organization_id == current_user.organization_id`
  (`app/api/routers/cases.py`). There is no cross-tenant "super view" in
  the current API surface; a future platform-admin cross-org view would
  need to be a deliberate, explicitly-audited addition.

## Input handling / injection resistance

- All database access goes through SQLAlchemy's parameterized query
  builder — no raw string-interpolated SQL anywhere in the codebase.
- File uploads are restricted by extension (`.eml` only, for now) and by
  size (`MAX_UPLOAD_SIZE_MB`, default 25MB, enforced before any parsing
  is attempted).
- Evidence storage paths are derived only from a server-generated UUID
  (the case ID) and a content hash — never from user-supplied filenames
  — and `_safe_case_dir()` explicitly checks the resolved path stays
  inside `EVIDENCE_STORAGE_PATH` before writing, guarding against path
  traversal even if that assumption is ever violated upstream.
- Email parsing uses Python's standard `email` package with
  `policy.default`, which is RFC-compliant and does not execute or
  evaluate any content — HTML bodies are stored as text for analysis,
  never rendered or executed server-side.

## Error handling / information disclosure

- A global exception handler (`app/main.py`) returns a generic 500 to
  clients for any unhandled exception; stack traces are never included
  in API responses (they still go to server-side logs for debugging).
- Auth error messages are deliberately generic ("Incorrect email or
  password") rather than distinguishing "no such user" from "wrong
  password," to avoid account enumeration.

## Audit trail

- `audit_logs` is append-only (no `updated_at`, no update code path
  anywhere touches existing rows) and records actor, action, resource,
  and a JSON detail blob for register/login/case-creation events today,
  with `record_audit_event()` designed to be called from any future
  sensitive action (escalation, export, role change, etc.).

## Secrets & configuration

- All secrets/config are environment-variable driven
  (`app/core/config.py`, `.env.example`) — nothing is hardcoded in
  source. `.env` is git-ignored (see `.gitignore`).
- Threat-intel API keys (`VIRUSTOTAL_API_KEY`, etc.) are optional; the
  platform runs in a fully offline/demo mode without them rather than
  silently failing or fabricating results.

## Brute-force mitigation

- `POST /auth/login` and `POST /auth/register` are rate-limited to
  10 requests/minute per client address (`slowapi`, shared `Limiter`
  instance in `app/core/limiter.py`) — a 429 is returned once exceeded.
- Accounts lock for 15 minutes after 5 consecutive failed login
  attempts (`User.failed_login_attempts`/`locked_until`,
  `app/services/auth_service.py::authenticate_user`); the counter
  resets on any successful login. A locked account returns 423, distinct
  from the generic 401 for an ordinary wrong password.

## Known gaps (tracked, not hidden)

- No 2FA/MFA.
- CORS defaults to `allow_origins=["*"]` when `DEBUG=true` for local
  development convenience; this **must** be restricted to real frontend
  origin(s) in any non-local deployment (see `app/main.py`).
- Refresh tokens do not yet support per-device/session listing or
  "log out all devices" — only single-token revocation (via rotation)
  exists.
