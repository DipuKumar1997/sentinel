"""Turns threat-intelligence enrichment observations into explainable
findings, on equal footing with the deterministic header/URL engines --
external/internal reputation data augments the risk score, it never
replaces the other evidence.
"""
from __future__ import annotations

from app.services.analysis_engines.header_forensics import Finding
from app.services.threat_intel import EnrichmentObservation

ENGINE_NAME = "threat_intelligence"

_VERDICT_SEVERITY = {
    "malicious": "critical",
    "suspicious": "medium",
    "unknown": "info",
    "clean": "info",
}
_VERDICT_CONFIDENCE = {
    "malicious": 0.9,
    "suspicious": 0.5,
    "unknown": 0.15,
    "clean": 0.2,
}


def run(observations_by_value: dict[str, list[EnrichmentObservation]]) -> list[Finding]:
    findings: list[Finding] = []

    for value, observations in observations_by_value.items():
        for obs in observations:
            if obs.verdict in ("clean", "unknown"):
                # Not worth surfacing as a standalone finding -- absence of
                # bad reputation isn't itself a signal, and cluttering the
                # findings list with "unknown" entries per IOC would drown
                # out the signals that matter.
                continue

            provider_label = obs.provider + (" (offline heuristic)" if obs.is_synthetic_demo_data else "")
            findings.append(
                Finding(
                    engine=ENGINE_NAME,
                    code=f"THREAT_INTEL_{obs.verdict.upper()}",
                    severity=_VERDICT_SEVERITY.get(obs.verdict, "low"),
                    confidence=_VERDICT_CONFIDENCE.get(obs.verdict, 0.3),
                    description=(
                        f"{provider_label} rated '{value}' as {obs.verdict}."
                    ),
                    evidence_ref=f"ioc:{value}",
                )
            )

    return findings
