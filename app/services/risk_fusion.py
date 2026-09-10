"""Combines findings from all analysis engines into a single explainable
risk score.

Deliberately simple and auditable for the prototype: a weighted-sum model
over rule severities/confidences, NOT a black-box ML ensemble, so every
point of the score can be traced back to a specific finding. ML model
predictions (see ModelPrediction) are incorporated as additional weighted
findings alongside the deterministic ones, never as the sole determinant.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.analysis_engines.header_forensics import Finding

_SEVERITY_WEIGHTS = {
    "info": 2,
    "low": 8,
    "medium": 18,
    "high": 32,
    "critical": 50,
}


@dataclass
class FusedRisk:
    score: int  # 0-100
    classification: str  # benign|suspicious|likely_malicious|malicious
    confidence_band: str  # low|medium|high
    rationale_summary: str


def _classify(score: int) -> str:
    if score >= 75:
        return "malicious"
    if score >= 50:
        return "likely_malicious"
    if score >= 25:
        return "suspicious"
    return "benign"


def _confidence_band(findings: list[Finding]) -> str:
    if not findings:
        return "low"
    avg_conf = sum(f.confidence for f in findings) / len(findings)
    if avg_conf >= 0.65:
        return "high"
    if avg_conf >= 0.4:
        return "medium"
    return "low"


def fuse(findings: list[Finding]) -> FusedRisk:
    if not findings:
        return FusedRisk(
            score=0,
            classification="benign",
            confidence_band="low",
            rationale_summary="No suspicious indicators were identified by any analysis engine.",
        )

    raw_total = 0.0
    for f in findings:
        raw_total += _SEVERITY_WEIGHTS.get(f.severity, 5) * f.confidence

    # Diminishing returns so a long tail of low-severity findings can't by
    # itself drag the score to "malicious".
    score = min(100, round(raw_total ** 0.85))

    classification = _classify(score)
    confidence_band = _confidence_band(findings)

    top_findings = sorted(findings, key=lambda f: _SEVERITY_WEIGHTS.get(f.severity, 0) * f.confidence, reverse=True)[:3]
    rationale_lines = [f"- [{f.severity.upper()}] {f.code}: {f.description}" for f in top_findings]
    rationale_summary = (
        f"Risk score {score}/100 ({classification}). Top contributing findings:\n"
        + "\n".join(rationale_lines)
    )

    return FusedRisk(
        score=score,
        classification=classification,
        confidence_band=confidence_band,
        rationale_summary=rationale_summary,
    )
