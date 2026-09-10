import pytest


async def _register_verify_login(client, email="alice@acmecorp.com", organization_name="Acme Corp"):
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Analyst",
            "email": email,
            "password": "SuperSecret123!",
            "organization_name": organization_name,
        },
    )
    assert r.status_code == 201
    token = r.json()["message"].split("verification_token=")[-1]
    r = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": "SuperSecret123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.mark.asyncio
async def test_reject_non_eml_upload(client):
    access_token = await _register_verify_login(client)
    files = {"file": ("not_an_email.txt", b"hello world", "text/plain")}
    r = await client.post(
        "/api/v1/ingestion/eml",
        headers={"Authorization": f"Bearer {access_token}"},
        files=files,
    )
    assert r.status_code == 415


@pytest.mark.asyncio
async def test_reject_empty_file(client):
    access_token = await _register_verify_login(client)
    files = {"file": ("empty.eml", b"", "message/rfc822")}
    r = await client.post(
        "/api/v1/ingestion/eml",
        headers={"Authorization": f"Bearer {access_token}"},
        files=files,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_phishing_email_flagged_malicious(client, sample_phish_eml_bytes):
    access_token = await _register_verify_login(client)
    files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post(
        "/api/v1/ingestion/eml",
        headers={"Authorization": f"Bearer {access_token}"},
        files=files,
    )
    assert r.status_code == 201
    body = r.json()
    case_id = body["case"]["id"]
    assert len(body["evidence_sha256"]) == 64  # sha256 hex digest length

    r = await client.get(
        f"/api/v1/cases/{case_id}/risk-score", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r.status_code == 200
    risk = r.json()
    assert risk["classification"] in ("suspicious", "likely_malicious", "malicious")
    assert risk["score"] >= 50

    r = await client.get(
        f"/api/v1/cases/{case_id}/findings", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r.status_code == 200
    findings = r.json()
    codes = {f["code"] for f in findings}
    assert "SPF_FAIL" in codes
    assert "URL_USES_RAW_IP" in codes


@pytest.mark.asyncio
async def test_benign_email_scores_low(client, sample_benign_eml_bytes):
    access_token = await _register_verify_login(client)
    files = {"file": ("sample_benign.eml", sample_benign_eml_bytes, "message/rfc822")}
    r = await client.post(
        "/api/v1/ingestion/eml",
        headers={"Authorization": f"Bearer {access_token}"},
        files=files,
    )
    assert r.status_code == 201
    case_id = r.json()["case"]["id"]

    r = await client.get(
        f"/api/v1/cases/{case_id}/risk-score", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r.status_code == 200
    risk = r.json()
    assert risk["classification"] == "benign"
    assert risk["score"] < 25


@pytest.mark.asyncio
async def test_tenant_isolation_between_organizations(client, sample_phish_eml_bytes):
    token_a = await _register_verify_login(client, email="alice@acmecorp.com")
    files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post(
        "/api/v1/ingestion/eml", headers={"Authorization": f"Bearer {token_a}"}, files=files
    )
    case_id = r.json()["case"]["id"]

    token_b = await _register_verify_login(client, email="carol@othercorp.com", organization_name="Other Corp")
    r = await client.get(
        f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {token_b}"}
    )
    assert r.status_code == 404
