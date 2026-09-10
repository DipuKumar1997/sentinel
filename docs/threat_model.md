# Threat Model — What This Platform Detects Against

This document describes the email-based attack techniques SentinelMail
AI is designed to surface evidence for, what signal each analysis engine
currently checks, and — importantly — what it does **not** yet check, so
analysts calibrate trust in the risk score correctly.

## Attack categories in scope

| Category | Example | Primary signals used |
|---|---|---|
| Credential phishing | Fake "verify your account" page | SPF/DKIM/DMARC fail, raw-IP links, URL shorteners, urgency language |
| Business Email Compromise (BEC) | Impersonating an executive/vendor via display-name spoofing | Display-name/brand mismatch, Reply-To domain mismatch |
| Malware delivery | Malicious attachment (macro-enabled doc, archive) | Attachment hash IOC recording, archive/macro flags (enrichment pending) |
| Domain spoofing / lookalikes | `paypa1-secure.top` instead of `paypal.com` | Low-reputation TLD heuristic, SPF/DMARC fail on claimed domain |
| Link-based evasion | Shortened URLs, IP-literal links, insecure login pages | URL/domain analysis engine |

## Per-signal honesty notes

**SPF** — Read directly from the `Authentication-Results` header added
by the recipient's own receiving MTA when present (source: `header`).
If absent, a live DNS TXT lookup for `v=spf1` confirms *policy
existence* only (source: `live_check`) — this is **not** a full RFC 7208
evaluation against the connecting IP and does not by itself produce a
pass/fail verdict.

**DKIM** — Read from `Authentication-Results` only. This checkpoint does
**not** perform cryptographic DKIM signature re-verification (which
requires the exact original body bytes plus the signer's published
public key). If no `Authentication-Results` header is present, DKIM
status is reported as unavailable rather than guessed.

**DMARC** — Same header-based approach as SPF, with a live `_dmarc.<domain>`
TXT lookup fallback that reports policy presence, not full
SPF/DKIM-identifier-alignment evaluation.

**Received-header hop chain** — Best-effort regex-based parsing. Modern
MTAs are not fully standardized in their `Received:` header format, so
each hop carries a `parse_confidence` (`high`/`medium`/`low`) rather
than being silently trusted. A message where none of the hops parse
confidently is itself flagged (`RELAY_CHAIN_UNRELIABLE`) so an analyst
knows to inspect manually.

**IP geolocation** — The `IPAddress` model has `approx_lat`/`approx_lon`/
`approx_city` fields explicitly documented as **infrastructure**
geolocation (hosting provider/ASN location), never a claim about a
physical attacker's location. This distinction matters: attackers
routinely operate through VPNs, compromised infrastructure, and cloud
hosting far from their actual location. No enrichment provider is
called yet in this checkpoint (see `NEXT_STEPS.md`) — these fields are
schema-ready but unpopulated until that phase.

**Attachment analysis** — Currently: SHA-256 hashing and archive/macro
filename-extension heuristics only. Deep content inspection (macro
extraction, sandboxed detonation, embedded-object scanning) is out of
scope for this checkpoint.

**ML model predictions** — `phishing_classifier_lr` (see
`app/services/ml_scoring.py`) is a real, fitted scikit-learn
`LogisticRegression`, not a hand-weighted formula — but it was trained
on **synthetically generated** feature combinations (`scripts/train_model.py`),
because no real-world labeled email corpus was available in this
environment. Its `model_version` string is suffixed `-synthetic` and
every finding it produces states this caveat explicitly. Treat its
predictions as demonstrating the pipeline works end-to-end, not as
validated against real phishing traffic.

## What "risk score" does and doesn't mean

The fused 0–100 score (`app/services/risk_fusion.py`) is a **triage
aid**, not a legal or definitive verdict. It:

- IS: a transparent, re-derivable sum of specific, named findings, each
  independently visible via `GET /cases/{id}/findings`.
- IS NOT: a claim of confirmed malicious intent, a substitute for human
  analyst review before any action against a real sender, or a
  probability calibrated against a labeled ground-truth dataset (no ML
  model is trained/integrated yet in this checkpoint).

## Adversarial considerations already accounted for

- An attacker who spoofs a display name but can't control the actual
  sending domain is caught by `DISPLAY_NAME_BRAND_MISMATCH` regardless
  of SPF/DKIM status.
- An attacker who passes SPF (e.g. by using a compromised legitimate
  account) is not treated as automatically benign — SPF pass reduces
  weight but content-based (URL/urgency) signals are evaluated
  independently.
- The evidence pipeline never trusts a single header/field as ground
  truth about identity — see `docs/architecture.md` section 3.

## Adversarial considerations NOT yet handled (tracked)

- No sandboxed URL/attachment detonation — links/attachments are never
  fetched or executed by the platform itself.
- No homograph/IDN-lookalike-domain detection (e.g. Cyrillic character
  substitution) yet.
- No cross-case campaign correlation yet, so a coordinated multi-target
  campaign using varied infrastructure per message won't be visibly
  linked until that phase ships.
