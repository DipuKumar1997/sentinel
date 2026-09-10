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
async def test_threat_intel_and_ml_findings_present(client, sample_phish_eml_bytes):
    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}
    files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers=headers, files=files)
    assert r.status_code == 201
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
    assert r.status_code == 200
    findings = r.json()
    engines = {f["engine"] for f in findings}
    # The .top TLD in the sample fixture should trigger the offline
    # threat-intel heuristic provider, and the auth-failure + urgency
    # language should push the heuristic ML scaffold's probability high
    # enough to surface a finding.
    assert "threat_intelligence" in engines
    assert "ml_model_structural" in engines


@pytest.mark.asyncio
async def test_case_report_pdf_format(client, sample_phish_eml_bytes):
    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}
    files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers=headers, files=files)
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/report?format=pdf", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"
    assert len(r.content) > 500  # a real, non-trivial PDF was produced


@pytest.mark.asyncio
async def test_case_report_is_generated_and_downloadable(client, sample_phish_eml_bytes):
    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}
    files = {"file": ("sample_phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers=headers, files=files)
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "SentinelMail AI" in r.text
    assert "Risk Assessment" in r.text
    assert "Analysis Findings" in r.text


@pytest.mark.asyncio
async def test_report_requires_authentication(client):
    r = await client.get("/api/v1/cases/00000000-0000-0000-0000-000000000000/report")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_campaign_created_when_two_cases_share_iocs(client, sample_phish_eml_bytes):
    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}

    r1 = await client.post(
        "/api/v1/ingestion/eml", headers=headers,
        files={"file": ("phish1.eml", sample_phish_eml_bytes, "message/rfc822")},
    )
    assert r1.status_code == 201

    r = await client.get("/api/v1/campaigns", headers=headers)
    assert r.status_code == 200
    assert r.json() == []  # no campaign yet with only one case

    r2 = await client.post(
        "/api/v1/ingestion/eml", headers=headers,
        files={"file": ("phish2.eml", sample_phish_eml_bytes, "message/rfc822")},
    )
    assert r2.status_code == 201

    r = await client.get("/api/v1/campaigns", headers=headers)
    assert r.status_code == 200
    campaigns = r.json()
    assert len(campaigns) == 1
    assert campaigns[0]["detection_method"] == "shared_ioc"

    r = await client.get(f"/api/v1/campaigns/{campaigns[0]['id']}/cases", headers=headers)
    assert r.status_code == 200
    memberships = r.json()
    assert len(memberships) == 2


@pytest.mark.asyncio
async def test_msg_upload_end_to_end(client):
    """Full HTTP round-trip for the .msg endpoint, using a mocked
    extract_msg backend (see tests/test_msg_parser.py for why a real
    binary .msg fixture isn't used) patched at the ingestion call site.
    """
    from unittest.mock import MagicMock, patch

    from app.services import msg_parser

    fake = MagicMock()
    fake.header = (
        "From: \"PayPal Security\" <alerts@paypa1-secure.top>\r\n"
        "Reply-To: attacker@totally-different-domain.xyz\r\n"
        "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Message-ID: <abc123@paypa1-secure.top>\r\n"
    )
    fake.sender_email = "alerts@paypa1-secure.top"
    fake.sender_name = "PayPal Security"
    fake.sender = "\"PayPal Security\" <alerts@paypa1-secure.top>"
    fake.to = "victim@acmecorp.com"
    fake.cc = ""
    fake.date = "Mon, 01 Sep 2025 10:14:55 +0000"
    fake.subject = "Urgent Action Required"
    fake.body = "Please verify your account immediately, click http://203.0.113.99/login"
    fake.htmlBody = None
    fake.attachments = []
    fake.close = MagicMock()

    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}

    with patch("app.services.msg_parser.extract_msg.Message", return_value=fake):
        r = await client.post(
            "/api/v1/ingestion/msg",
            headers=headers,
            files={"file": ("suspicious.msg", b"fake ole bytes", "application/vnd.ms-outlook")},
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["case"]["status"] == "analyzing"
    case_id = body["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/risk-score", headers=headers)
    assert r.status_code == 200
    assert r.json()["score"] > 0


@pytest.mark.asyncio
async def test_msg_upload_rejects_wrong_extension(client):
    access_token = await _register_verify_login(client)
    headers = {"Authorization": f"Bearer {access_token}"}
    r = await client.post(
        "/api/v1/ingestion/msg", headers=headers,
        files={"file": ("not_a_msg.eml", b"hello", "message/rfc822")},
    )
    assert r.status_code == 415


@pytest.mark.asyncio
async def test_campaigns_are_tenant_isolated(client, sample_phish_eml_bytes):
    token_a = await _register_verify_login(client, email="alice@acmecorp.com", organization_name="Acme Corp")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    await client.post(
        "/api/v1/ingestion/eml", headers=headers_a,
        files={"file": ("p1.eml", sample_phish_eml_bytes, "message/rfc822")},
    )
    await client.post(
        "/api/v1/ingestion/eml", headers=headers_a,
        files={"file": ("p2.eml", sample_phish_eml_bytes, "message/rfc822")},
    )

    token_b = await _register_verify_login(client, email="carol@othercorp.com", organization_name="Other Corp")
    headers_b = {"Authorization": f"Bearer {token_b}"}
    r = await client.get("/api/v1/campaigns", headers=headers_b)
    assert r.status_code == 200
    assert r.json() == []  # Org B sees none of Org A's campaigns
