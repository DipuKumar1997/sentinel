# Forensic Workflow & Chain of Custody

This document describes how evidence integrity is maintained from the
moment a suspicious email is submitted through to analyst review, so
findings remain defensible if a case escalates to legal/HR/law
enforcement action.

## 1. Preserve before you parse

`ingest_eml_and_create_case()` (`app/services/ingestion.py`) hashes and
persists the raw uploaded bytes **before** attempting to parse them. If
parsing fails for any reason (malformed MIME, unexpected encoding), the
raw evidence is still safely stored and hashed, and the case is routed
to `triage` status with a note requiring manual analyst review — nothing
is silently dropped.

## 2. Content-addressed, read-only storage

`app/services/evidence_storage.py::store_evidence_bytes()`:

1. Computes SHA-256 of the exact bytes received.
2. Writes them to `<EVIDENCE_STORAGE_PATH>/<case_id>/<sha256><suffix>`.
3. `chmod 0o440` (read-only) immediately after writing.
4. If a file with that hash already exists, it is not rewritten —
   naturally deduplicating identical evidence without weakening
   integrity (the hash is still recorded fresh in `evidence_hashes` for
   this evidence object).

This means: given only a stored file and its recorded hash, anyone can
independently verify the file hasn't been altered since ingestion by
recomputing its SHA-256 and comparing.

## 3. Every hash is a separate, append-only record

`EvidenceHash` rows are never updated — only inserted. This means the
audit trail of "what hash did we record, and when" survives even if
(hypothetically) `EvidenceObject.storage_uri` metadata were later
edited, since the original hash commitment is a separate, immutable row.

## 4. Headers preserved verbatim, in original order

`EmailHeader` stores every header exactly as it appeared, including
duplicates (e.g. multiple `Received:` lines), with an explicit
`sequence` column preserving original order. No header is normalized,
deduplicated, or dropped at ingest time — normalization (like the
Received-hop parsing) is stored as a **separate, derived** table
(`ReceivedHop`) that always points back to the source record, so the
raw header is always available to re-derive from if the parser's
heuristics are ever disputed or improved.

## 5. Case status history is append-only

`CaseStatusHistory` records every transition (`from_status` →
`to_status`) with a timestamp and, where applicable, the acting user —
never overwriting the previous state. Combined with `AuditLog`, this
gives a full timeline: who touched the case, what changed, and when.

## 6. Reporter identity vs. evidence content are structurally separate

See `docs/architecture.md` section 3 — `Case.reporter_user_id` always
comes from the authenticated session, `SenderIdentity`/`EmailMessage.from_address`
always come from parsed (untrusted) content. This separation itself *is*
a chain-of-custody control: it means "who reported this" can never be
silently overwritten by "what the email claims," even by a parsing bug.

## 7. What a future export/report will need to include (scaffolded, not yet built)

The `Report` / `ReportTemplate` models exist so that a future PDF/HTML
export can assemble, per case: the recorded SHA-256 of the original
`.eml`, the full findings list with engine/confidence per finding, the
case status history, and the audit log entries for that case's
`resource_id` — giving a reviewer everything needed to independently
reconstruct how the platform reached its risk score, without relying on
the platform's continued availability.
