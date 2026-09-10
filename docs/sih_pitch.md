# SentinelMail AI — SIH26106 Pitch Notes

## The problem

Organizations rely on employees to "just forward it to IT" when they get
a suspicious email. What actually happens next is usually manual,
slow, and inconsistent: a security analyst opens the raw headers by
hand, greps for IPs, maybe pastes a URL into VirusTotal, and writes up a
verdict from memory of past cases. There's no structured evidence trail,
no consistent scoring, and no way to see if the same phishing
infrastructure hit five other people in the org last week.

## What SentinelMail AI does differently

1. **Verified reporting identity.** The person reporting an email is
   authenticated by the platform — not assumed from whatever the email
   itself claims. This closes a subtle but real gap: a malicious email
   could otherwise "claim" to be from anyone, and naive systems that key
   off the email's own `From` header for anything security-relevant
   inherit that same untrustworthy source.
2. **Evidence-first, not verdict-first.** Every byte of the submitted
   email is hashed and preserved before any analysis touches it. If the
   case ever needs to go further (HR, legal, law enforcement), the chain
   of custody already exists.
3. **Explainable, not black-box.** The risk score is a transparent sum
   of named findings (`SPF_FAIL`, `DISPLAY_NAME_BRAND_MISMATCH`,
   `URL_USES_RAW_IP`, ...), each independently visible to the analyst —
   not a single opaque number from an uninspectable model.
4. **Built to grow, not thrown away.** The 41-table schema already has
   the shape for campaign correlation, threat-intel enrichment, and ML
   model integration — this checkpoint proves the foundation works
   end-to-end before those layers are added.

## Live demo script (2 minutes)

1. Register as `analyst@democorp.com` (organization auto-created from
   the email domain), verify, log in.
2. Submit `tests/fixtures/sample_phish.eml` via `/ingestion/eml`.
3. Show the response: case created, risk score **78/100 (malicious)**
   in under a second.
4. Open `/cases/{id}/findings` — walk through the 11 findings: SPF/DKIM/
   DMARC all failing, a PayPal-branded display name on a `.top` domain
   that isn't PayPal's, a raw-IP link, a URL shortener, urgency language
   in the body.
5. Submit `tests/fixtures/sample_benign.eml` for contrast — same
   pipeline, scores **0/100 (benign)**, no findings fire.
6. Point out: this isn't a demo-only shortcut — it's the same
   deterministic code path for both, provably (see `tests/test_ingestion.py`).

## Judging criteria alignment

- **Technical depth**: real RFC 5322/MIME parsing, real SPF/DMARC DNS
  lookups, a normalized 41-table schema, JWT+Argon2 auth, tenant
  isolation — not a mockup.
- **Feasibility**: runs today via `docker compose up`; every claim in
  this pitch is backed by a passing automated test.
- **Honesty**: `docs/threat_model.md` explicitly documents what is and
  isn't implemented yet (e.g., no full DKIM crypto verification, no
  threat-intel API calls yet) rather than overstating capability.
- **Extensibility**: campaign detection, graph correlation, ML models,
  and reporting are schema-ready extension points, not afterthoughts.
