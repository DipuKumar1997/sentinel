"""Deterministic, rule-based analysis engine over header/auth evidence.

This is one of several independent "analysis engines" whose findings are
combined by the risk-fusion layer (`app.services.risk_fusion`). It never
produces a final verdict on its own.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.auth_results import AuthFinding
from app.services.eml_parser import ParsedEmail
from app.services.ioc_extraction import detect_display_name_mismatch


@dataclass
class Finding:
    engine: str
    code: str
    severity: str  # info|low|medium|high|critical
    confidence: float
    description: str
    evidence_ref: str | None = None


ENGINE_NAME = "header_forensics"


def run(parsed: ParsedEmail, auth_findings: list[AuthFinding]) -> list[Finding]:
    findings: list[Finding] = []

    for auth in auth_findings:
        if auth.mechanism == "spf" and auth.result in ("fail", "softfail"):
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="SPF_FAIL",
                    severity="high" if auth.result == "fail" else "medium",
                    confidence=0.85,
                    description=(
                        f"SPF check returned '{auth.result}' for domain "
                        f"{auth.domain or 'unknown'}. The sending IP is not "
                        "authorized to send on behalf of this domain."
                    ),
                )
            )
        if auth.mechanism == "dkim" and auth.result == "fail":
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="DKIM_FAIL",
                    severity="high",
                    confidence=0.8,
                    description="DKIM signature verification failed or was not present as expected.",
                )
            )
        if auth.mechanism == "dmarc" and auth.result == "fail":
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="DMARC_FAIL",
                    severity="high",
                    confidence=0.85,
                    description="DMARC policy evaluation failed, indicating SPF/DKIM alignment issues.",
                )
            )

    if detect_display_name_mismatch(parsed.from_display_name, parsed.from_address):
        findings.append(
            Finding(
                engine=ENGINE_NAME,
                code="DISPLAY_NAME_BRAND_MISMATCH",
                severity="high",
                confidence=0.6,
                description=(
                    f"Display name '{parsed.from_display_name}' suggests a known brand "
                    f"or role, but the sending address '{parsed.from_address}' does not "
                    "match that brand's domain. Common in impersonation/BEC attempts."
                ),
            )
        )

    if parsed.reply_to_address and parsed.from_address:
        from_domain = parsed.from_address.rsplit("@", 1)[-1].lower()
        reply_domain = parsed.reply_to_address.rsplit("@", 1)[-1].lower()
        if from_domain != reply_domain:
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="REPLY_TO_DOMAIN_MISMATCH",
                    severity="medium",
                    confidence=0.55,
                    description=(
                        f"Reply-To domain '{reply_domain}' differs from the From domain "
                        f"'{from_domain}'. Replies would be routed away from the apparent sender."
                    ),
                )
            )

    if parsed.return_path and parsed.from_address:
        from_domain = parsed.from_address.rsplit("@", 1)[-1].lower()
        return_domain = parsed.return_path.rsplit("@", 1)[-1].lower() if "@" in parsed.return_path else None
        if return_domain and return_domain != from_domain:
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code="RETURN_PATH_MISMATCH",
                    severity="low",
                    confidence=0.4,
                    description=(
                        f"Return-Path domain '{return_domain}' differs from the From domain "
                        f"'{from_domain}'. This alone is common with legitimate mailing "
                        "infrastructure, but adds weight combined with other signals."
                    ),
                )
            )

    low_confidence_hops = [h for h in parsed.received_hops if h.parse_confidence == "low"]
    if len(low_confidence_hops) == len(parsed.received_hops) and parsed.received_hops:
        findings.append(
            Finding(
                engine=ENGINE_NAME,
                code="RELAY_CHAIN_UNRELIABLE",
                severity="info",
                confidence=0.3,
                description=(
                    "None of the Received: hops could be parsed with confidence. "
                    "Relay path reconstruction may be incomplete or the headers were "
                    "altered/stripped."
                ),
            )
        )

    if not auth_findings:
        findings.append(
            Finding(
                engine=ENGINE_NAME,
                code="NO_AUTH_RESULTS_HEADER",
                severity="info",
                confidence=0.2,
                description=(
                    "No Authentication-Results header was present on the submitted message. "
                    "SPF/DKIM/DMARC verdicts could not be read from headers; a live DNS-based "
                    "check was attempted separately where possible."
                ),
            )
        )

    return findings
