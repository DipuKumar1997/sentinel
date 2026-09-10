"""Structural/header-feature model-prediction service.

One of two independent models feeding risk fusion -- see
`app/services/ml_common.py` for how this relates to
`ml_scoring_text.py`, the real-data text-content model.

Loads the trained `phishing_classifier_lr` bundle (see
`scripts/train_model.py`) at import time if present, and falls back to
`heuristic_model_v0` -- a transparent, hand-weighted scoring function --
if the model artifact is missing. Either path populates the same
`ModelOutput` shape.

Honesty note (see docs/threat_model.md): this model was fit on
**synthetically generated** feature combinations (no real-world labeled
corpus was available for these specific structural signals -- e.g. no
dataset exists that pairs SPF/DKIM results with ground-truth labels).
Its `model_version` string is suffixed `-synthetic` for exactly this
reason. Contrast with `ml_scoring_text.py`, which IS trained on real
labeled email text.
"""
from __future__ import annotations

import math
from pathlib import Path

from app.services.analysis_engines.header_forensics import Finding
from app.services.auth_results import AuthFinding
from app.services.eml_parser import ParsedEmail
from app.services.ml_common import ModelOutput
from app.services.ml_features import extract_feature_vector

_MODEL_PATH = Path(__file__).resolve().parent.parent / "ml_models" / "phishing_classifier.joblib"

HEURISTIC_MODEL_NAME = "heuristic_model_v0"
HEURISTIC_MODEL_VERSION = "0.1.0"

_URGENCY_TERMS = (
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "confirm your password", "unusual activity", "will be closed",
)


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _load_trained_bundle():
    if not _MODEL_PATH.exists():
        return None
    try:
        import joblib

        return joblib.load(_MODEL_PATH)
    except Exception:
        return None


_TRAINED_BUNDLE = _load_trained_bundle()


def _score_with_trained_model(
    parsed: ParsedEmail, auth_findings: list[AuthFinding], domains: set[str], urls: set[str]
) -> ModelOutput:
    bundle = _TRAINED_BUNDLE
    features = extract_feature_vector(parsed, auth_findings, domains, urls)
    probability = float(bundle["model"].predict_proba([features])[0][1])  # P(phishing)

    display_mismatch = features[2] >= 1.0
    if probability >= 0.5 and display_mismatch:
        label = "bec"
    elif probability >= 0.5:
        label = "phishing"
    else:
        label = "benign"

    return ModelOutput(
        model_name=bundle["model_name"],
        model_version=bundle["model_version"],
        label=label,
        probability=round(probability, 4),
        is_external_model=False,
    )


def _score_with_heuristic(
    parsed: ParsedEmail, auth_findings: list[AuthFinding], iocs_url_count: int
) -> ModelOutput:
    auth_fail_count = sum(1 for f in auth_findings if f.result in ("fail", "softfail"))

    body_text = (parsed.body_text or "") + " " + (parsed.body_html or "")
    body_lower = body_text.lower()
    urgency_hits = sum(1 for term in _URGENCY_TERMS if term in body_lower)

    display_mismatch = 1.0 if (
        parsed.from_display_name
        and parsed.from_address
        and parsed.reply_to_address
        and parsed.reply_to_address.rsplit("@", 1)[-1].lower()
        != parsed.from_address.rsplit("@", 1)[-1].lower()
    ) else 0.0

    z = (
        -3.0
        + 1.3 * auth_fail_count
        + 0.6 * urgency_hits
        + 1.1 * display_mismatch
        + 0.35 * min(iocs_url_count, 5)
    )
    probability = _sigmoid(z)

    if probability >= 0.5 and display_mismatch:
        label = "bec"
    elif probability >= 0.5:
        label = "phishing"
    else:
        label = "benign"

    return ModelOutput(
        model_name=HEURISTIC_MODEL_NAME,
        model_version=HEURISTIC_MODEL_VERSION,
        label=label,
        probability=round(probability, 4),
        is_external_model=False,
    )


def score_email(
    parsed: ParsedEmail,
    auth_findings: list[AuthFinding],
    iocs_url_count: int,
    domains: set[str] | None = None,
    urls: set[str] | None = None,
) -> ModelOutput:
    """Scores an email using the trained structural model if available,
    else the heuristic fallback.
    """
    if _TRAINED_BUNDLE is not None and domains is not None and urls is not None:
        try:
            return _score_with_trained_model(parsed, auth_findings, domains, urls)
        except Exception:
            pass
    return _score_with_heuristic(parsed, auth_findings, iocs_url_count)


def model_output_to_finding(output: ModelOutput) -> Finding | None:
    if output.label == "benign" or output.probability < 0.5:
        return None

    if output.probability >= 0.8:
        severity = "high"
    elif output.probability >= 0.65:
        severity = "medium"
    else:
        severity = "low"

    is_trained = "synthetic" in output.model_version or output.model_name != HEURISTIC_MODEL_NAME
    caveat = (
        "This is a trained classifier fit on synthetically generated structural features "
        "(not real-world labeled traffic) -- see docs/threat_model.md."
        if is_trained
        else "This is a heuristic v0 scaffold, not a trained classifier -- see docs/threat_model.md."
    )

    return Finding(
        engine="ml_model_structural",
        code=f"STRUCTURAL_MODEL_PREDICTION_{output.label.upper()}",
        severity=severity,
        confidence=output.probability,
        description=(
            f"{output.model_name} (v{output.model_version}) predicted '{output.label}' "
            f"with probability {output.probability:.2f}. {caveat}"
        ),
    )
