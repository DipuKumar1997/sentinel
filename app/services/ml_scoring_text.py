"""Text-content model-prediction service.

The second of two independent models feeding risk fusion (see
`app/services/ml_common.py`). Loads `text_content_classifier.joblib`
(see `scripts/train_text_model.py`) at import time if present.

Unlike `ml_scoring_structural.py`, this model IS trained on real,
publicly available labeled email data (see `scripts/fetch_datasets.py`
and `data/README.md` for exact provenance) -- its predictions carry
real evidentiary weight, not just a pipeline demonstration.

Until you run `python -m scripts.fetch_datasets` and
`python -m scripts.train_text_model` yourself, `text_content_classifier.joblib`
does not exist and this module is a documented no-op: `score_email()`
returns `None` and no finding is produced, rather than fabricating a
prediction. Nothing else in the pipeline breaks in the meantime -- risk
fusion just runs with one fewer input, exactly as if this file weren't
here at all.
"""
from __future__ import annotations

from pathlib import Path

from app.services.analysis_engines.header_forensics import Finding
from app.services.eml_parser import ParsedEmail
from app.services.ml_common import ModelOutput

_MODEL_PATH = Path(__file__).resolve().parent.parent / "ml_models" / "text_content_classifier.joblib"


def _load_trained_bundle():
    if not _MODEL_PATH.exists():
        return None
    try:
        import joblib

        return joblib.load(_MODEL_PATH)
    except Exception:
        return None


_TRAINED_BUNDLE = _load_trained_bundle()


def is_available() -> bool:
    return _TRAINED_BUNDLE is not None


def _build_text(parsed: ParsedEmail) -> str:
    subject = parsed.subject or ""
    body = parsed.body_text or parsed.body_html or ""
    # Mirrors exactly how scripts/train_text_model.py -> dataset_loader
    # constructs its `text` column ("subject . body"), so inference-time
    # text matches training-time text.
    return f"{subject} . {body}".strip()


def score_email(parsed: ParsedEmail) -> ModelOutput | None:
    if _TRAINED_BUNDLE is None:
        return None
    try:
        text = _build_text(parsed)
        if not text.strip():
            return None
        vectorizer = _TRAINED_BUNDLE["vectorizer"]
        model = _TRAINED_BUNDLE["model"]
        vec = vectorizer.transform([text])
        probability = float(model.predict_proba(vec)[0][1])  # P(phishing_or_spam)
        label = "phishing" if probability >= 0.5 else "benign"
        return ModelOutput(
            model_name=_TRAINED_BUNDLE["model_name"],
            model_version=_TRAINED_BUNDLE["model_version"],
            label=label,
            probability=round(probability, 4),
            is_external_model=False,
        )
    except Exception:
        # Inference-time failure (e.g. corrupt artifact, version skew)
        # degrades to "no prediction" rather than crashing ingestion.
        return None


def model_output_to_finding(output: ModelOutput) -> Finding | None:
    if output.label == "benign" or output.probability < 0.5:
        return None

    if output.probability >= 0.85:
        severity = "high"
    elif output.probability >= 0.65:
        severity = "medium"
    else:
        severity = "low"

    return Finding(
        engine="ml_model_text",
        code=f"TEXT_MODEL_PREDICTION_{output.label.upper()}",
        severity=severity,
        confidence=output.probability,
        description=(
            f"{output.model_name} (v{output.model_version}) predicted this message's TEXT CONTENT "
            f"is '{output.label}' with probability {output.probability:.2f}. Trained on real, "
            "publicly available labeled email data -- see data/README.md for exact sources."
        ),
    )
