"""Tests for the text-content ML model integration.

Since the real trained artifact (`text_content_classifier.joblib`) is
deliberately NOT shipped in this repo -- it's produced by running
`scripts/fetch_datasets.py` + `scripts/train_text_model.py` yourself on
real data -- these tests cover both states: the model absent (today's
default) and the model present (mocked, so the wiring into the
ingestion pipeline is verified without needing gigabytes of real data
in CI).
"""
from unittest.mock import MagicMock, patch

import pytest

from app.services import ml_scoring_text
from app.services.eml_parser import parse_eml_bytes


def test_text_model_absent_returns_none_gracefully():
    """With no model artifact on disk (the default state of this repo),
    score_email must return None rather than raising or fabricating a
    prediction.
    """
    with patch.object(ml_scoring_text, "_TRAINED_BUNDLE", None):
        assert ml_scoring_text.is_available() is False
        parsed = parse_eml_bytes(open("tests/fixtures/sample_phish.eml", "rb").read())
        result = ml_scoring_text.score_email(parsed)
        assert result is None


def test_text_model_present_produces_finding_when_mocked():
    """Mocks a trained bundle to verify the scoring + finding-conversion
    logic works correctly once a real artifact exists.
    """
    fake_model = MagicMock()
    fake_model.predict_proba.return_value = [[0.05, 0.95]]  # 95% phishing
    fake_vectorizer = MagicMock()
    fake_vectorizer.transform.return_value = "fake_vector"

    fake_bundle = {
        "vectorizer": fake_vectorizer,
        "model": fake_model,
        "model_name": "text_content_classifier",
        "model_version": "1.0.0-real-corpus",
    }

    with patch.object(ml_scoring_text, "_TRAINED_BUNDLE", fake_bundle):
        assert ml_scoring_text.is_available() is True
        parsed = parse_eml_bytes(open("tests/fixtures/sample_phish.eml", "rb").read())
        result = ml_scoring_text.score_email(parsed)

        assert result is not None
        assert result.label == "phishing"
        assert result.probability == 0.95
        assert result.model_name == "text_content_classifier"

        finding = ml_scoring_text.model_output_to_finding(result)
        assert finding is not None
        assert finding.engine == "ml_model_text"
        assert finding.severity == "high"
        assert "real, publicly available labeled email data" in finding.description


@pytest.mark.asyncio
async def test_ingestion_includes_text_model_finding_when_available(client, sample_phish_eml_bytes):
    """Full HTTP round-trip: with the text model mocked as present, its
    finding must appear alongside the structural model's finding in the
    case's findings list.
    """
    fake_model = MagicMock()
    fake_model.predict_proba.return_value = [[0.02, 0.98]]
    fake_vectorizer = MagicMock()
    fake_vectorizer.transform.return_value = "fake_vector"
    fake_bundle = {
        "vectorizer": fake_vectorizer,
        "model": fake_model,
        "model_name": "text_content_classifier",
        "model_version": "1.0.0-real-corpus",
    }

    from tests.test_enrichment_and_reporting import _register_verify_login

    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}

    with patch.object(ml_scoring_text, "_TRAINED_BUNDLE", fake_bundle):
        files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
        r = await client.post("/api/v1/ingestion/eml", headers=headers, files=files)
        assert r.status_code == 201
        case_id = r.json()["case"]["id"]

        r = await client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
        findings = r.json()
        engines = {f["engine"] for f in findings}
        assert "ml_model_text" in engines
        assert "ml_model_structural" in engines
