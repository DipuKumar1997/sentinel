"""Infrastructure-level analysis engine: turns origin resolution and IP
intelligence results into explainable findings, on equal footing with
every other engine feeding risk fusion.

Terminology discipline (per docs/threat_model.md): findings here
describe OBSERVED INFRASTRUCTURE, never a claim about the attacker's
identity or physical location.
"""
from __future__ import annotations

from app.services.analysis_engines.header_forensics import Finding
from app.services.ip_intelligence import IPIntelligenceResult
from app.services.origin_resolution import OriginResult

ENGINE_NAME = "infrastructure_analysis"


def origin_finding(origin: OriginResult) -> Finding:
    if not origin.determined:
        return Finding(
            engine=ENGINE_NAME,
            code="ORIGIN_UNDETERMINED",
            severity="info",
            confidence=0.0,
            description=(
                "Earliest reliable external origin IP could not be established. "
                + origin.reasoning_text
            ),
        )
    return Finding(
        engine=ENGINE_NAME,
        code="ORIGIN_ESTABLISHED",
        severity="info",
        confidence=origin.confidence,
        description=(
            f"Earliest reliable external origin IP: {origin.ip} (confidence {origin.confidence:.2f}). "
            + origin.reasoning_text
        ),
        evidence_ref=f"ip:{origin.ip}",
    )


def hosting_classification_finding(ip_address: str, intel: IPIntelligenceResult) -> Finding | None:
    if intel.hosting_classification != "hosting_datacenter":
        return None
    return Finding(
        engine=ENGINE_NAME,
        code="ORIGIN_IS_HOSTING_INFRASTRUCTURE",
        severity="low",
        confidence=0.6,
        description=(
            f"IP {ip_address} is classified as hosting/datacenter infrastructure "
            f"(source: {intel.hosting_classification_source}), rather than a residential "
            "or enterprise network. This is common for both legitimate bulk-mail senders "
            "and attacker-controlled infrastructure -- not evidence of maliciousness on its own."
        ),
        evidence_ref=f"ip:{ip_address}",
    )


def ptr_mismatch_finding(ip_address: str, ptr_hostname: str | None, from_domain: str | None) -> Finding | None:
    """Flags when the sending IP's reverse-DNS hostname shares no
    apparent relationship with the claimed From domain -- a signal, not
    a verdict (many legitimate senders use third-party mail infrastructure
    with unrelated PTR records).
    """
    if not ptr_hostname or not from_domain:
        return None
    from_domain_core = from_domain.split(".")[-2] if "." in from_domain else from_domain
    if from_domain_core.lower() not in ptr_hostname.lower():
        return Finding(
            engine=ENGINE_NAME,
            code="PTR_HOSTNAME_DOMAIN_MISMATCH",
            severity="info",
            confidence=0.3,
            description=(
                f"The sending IP's reverse-DNS hostname ('{ptr_hostname}') does not obviously "
                f"relate to the claimed sending domain ('{from_domain}'). This is common with "
                "third-party mail infrastructure and is not conclusive on its own."
            ),
            evidence_ref=f"ip:{ip_address}",
        )
    return None
