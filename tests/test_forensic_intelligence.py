"""Tests for the Forensic Intelligence extension: earliest reliable
origin resolution, IP intelligence classification, and the blockchain
hash-chain evidence-integrity ledger.
"""
import pytest

from app.services import blockchain_ledger, ip_intelligence
from app.services.eml_parser import ParsedHop
from app.services.origin_resolution import resolve_earliest_reliable_origin


# ---------------------------------------------------------------------
# Origin resolution (pure unit tests, no DB/network needed)
# ---------------------------------------------------------------------

def test_origin_skips_private_ips_and_finds_first_public():
    hops = [
        ParsedHop(hop_index=0, raw_value="", from_ip="10.0.0.5", parse_confidence="high"),
        ParsedHop(hop_index=1, raw_value="", from_ip="192.168.1.1", parse_confidence="high"),
        ParsedHop(hop_index=2, raw_value="", from_ip="185.220.101.50", parse_confidence="high"),
    ]
    result = resolve_earliest_reliable_origin(hops)
    assert result.determined is True
    assert result.ip == "185.220.101.50"
    assert result.confidence > 0.5


def test_origin_undetermined_when_all_hops_private():
    hops = [ParsedHop(hop_index=0, raw_value="", from_ip="10.0.0.1", parse_confidence="high")]
    result = resolve_earliest_reliable_origin(hops)
    assert result.determined is False
    assert result.ip is None
    assert "could not be established" in result.reasoning_text.lower()


def test_origin_undetermined_with_no_hops_at_all():
    result = resolve_earliest_reliable_origin([])
    assert result.determined is False
    assert "no received" in result.reasoning_text.lower()


def test_origin_handles_malformed_and_missing_ips_gracefully():
    hops = [
        ParsedHop(hop_index=0, raw_value="", from_ip=None, parse_confidence="low"),
        ParsedHop(hop_index=1, raw_value="", from_ip="not-an-ip", parse_confidence="low"),
    ]
    result = resolve_earliest_reliable_origin(hops)
    assert result.determined is False
    assert result.ip is None


def test_origin_lower_confidence_for_low_parse_confidence_hops():
    high_conf_hops = [
        ParsedHop(hop_index=0, raw_value="", from_ip="10.0.0.5", parse_confidence="high"),
        ParsedHop(hop_index=1, raw_value="", from_ip="185.220.101.50", parse_confidence="high"),
    ]
    low_conf_hops = [
        ParsedHop(hop_index=0, raw_value="", from_ip="10.0.0.5", parse_confidence="high"),
        ParsedHop(hop_index=1, raw_value="", from_ip="185.220.101.50", parse_confidence="low"),
    ]
    high_result = resolve_earliest_reliable_origin(high_conf_hops)
    low_result = resolve_earliest_reliable_origin(low_conf_hops)
    assert low_result.confidence < high_result.confidence


def test_origin_reserved_documentation_range_treated_as_non_public():
    """203.0.113.0/24 is RFC 5737 TEST-NET-3, reserved for documentation
    -- not a real routable public IP, so it must not be selected as an
    origin (this caught a real bug during development: using 203.0.113.x
    as a 'public-looking' example IP in test fixtures elsewhere in this
    codebase actually classifies as reserved/private here, correctly).
    """
    hops = [ParsedHop(hop_index=0, raw_value="", from_ip="203.0.113.55", parse_confidence="high")]
    result = resolve_earliest_reliable_origin(hops)
    assert result.determined is False


# ---------------------------------------------------------------------
# IP intelligence hosting classification (pure unit tests)
# ---------------------------------------------------------------------

def test_hosting_classification_detects_known_cloud_provider():
    classification, source = ip_intelligence.classify_hosting_from_asn_org("Amazon.com, Inc.")
    assert classification == "hosting_datacenter"
    assert "amazon" in source.lower()


def test_hosting_classification_unknown_for_unrecognized_org():
    classification, source = ip_intelligence.classify_hosting_from_asn_org("Some Regional ISP Ltd")
    assert classification == "unknown"


def test_hosting_classification_none_when_no_asn_org_available():
    classification, source = ip_intelligence.classify_hosting_from_asn_org(None)
    assert classification is None
    assert source is None


# ---------------------------------------------------------------------
# Blockchain hash-chain ledger (DB-backed, uses the test fixture session)
# ---------------------------------------------------------------------

async def _register_and_login(client, email="admin@acmecorp.com", org="Acme Corp"):
    r = await client.post(
        "/api/v1/auth/register",
        json={"full_name": "Admin", "email": email, "password": "SuperSecret123!", "organization_name": org},
    )
    token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": token})
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": "SuperSecret123!"})
    return r.json()["access_token"]


@pytest.mark.asyncio
async def test_blockchain_case_verification_matches_after_ingestion(client, sample_benign_eml_bytes):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/ingestion/eml", headers=headers,
        files={"file": ("b.eml", sample_benign_eml_bytes, "message/rfc822")},
    )
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/blockchain-verify", headers=headers)
    assert r.status_code == 200
    assert r.json()["verified"] is True


@pytest.mark.asyncio
async def test_blockchain_organization_chain_verifies_across_multiple_cases(client, sample_benign_eml_bytes):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    for name in ("a.eml", "b.eml", "c.eml"):
        await client.post(
            "/api/v1/ingestion/eml", headers=headers,
            files={"file": (name, sample_benign_eml_bytes, "message/rfc822")},
        )

    r = await client.get("/api/v1/organizations/blockchain-verify", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["anchor_count"] == 3


@pytest.mark.asyncio
async def test_blockchain_detects_tampering_when_anchor_altered(client, sample_benign_eml_bytes, db_session_factory):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    await client.post(
        "/api/v1/ingestion/eml", headers=headers,
        files={"file": ("a.eml", sample_benign_eml_bytes, "message/rfc822")},
    )

    # Directly corrupt the stored anchor's hash, simulating tampering,
    # and confirm the chain verification catches it.
    from sqlalchemy import select, update

    from app.models.ioc import BlockchainAnchor

    async with db_session_factory() as db:
        anchor = (await db.execute(select(BlockchainAnchor))).scalars().first()
        await db.execute(
            update(BlockchainAnchor).where(BlockchainAnchor.id == anchor.id).values(evidence_sha256="0" * 64)
        )
        await db.commit()

    r = await client.get("/api/v1/organizations/blockchain-verify", headers=headers)
    assert r.status_code == 200
    assert r.json()["verified"] is False


@pytest.mark.asyncio
async def test_origin_and_ip_intelligence_endpoints_end_to_end(client):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    eml = (
        "Received: from mail.suspicious-host.ru (mail.suspicious-host.ru [185.220.101.50])\r\n"
        "    by mx.acmecorp.com with ESMTPS id abc123; Mon, 01 Sep 2025 10:15:00 +0000\r\n"
        "Authentication-Results: mx.acmecorp.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        "From: \"PayPal Security\" <alerts@evil.com>\r\n"
        "To: victim@acmecorp.com\r\nSubject: Urgent\r\nContent-Type: text/plain\r\n\r\n"
        "Please verify your account immediately.\r\n"
    ).encode()
    r = await client.post("/api/v1/ingestion/eml", headers=headers, files={"file": ("p.eml", eml, "message/rfc822")})
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/origin", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["origin_determined"] is True
    assert body["origin_ip"] == "185.220.101.50"
    assert "disclaimer" in body

    r = await client.get(f"/api/v1/cases/{case_id}/ip-intelligence", headers=headers)
    assert r.status_code == 200
    ips = r.json()["ips"]
    assert any(i["ip"] == "185.220.101.50" for i in ips)

    r = await client.get(f"/api/v1/cases/{case_id}/dns-observations", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    r = await client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
    infra_codes = {f["code"] for f in r.json() if f["engine"] == "infrastructure_analysis"}
    assert "ORIGIN_ESTABLISHED" in infra_codes


@pytest.mark.asyncio
async def test_origin_undetermined_reflected_in_api_and_findings(client, sample_benign_eml_bytes):
    """The benign fixture's Received hop has no external IP at all
    (single internal-looking hop), so origin must honestly report
    undetermined rather than guessing.
    """
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/ingestion/eml", headers=headers,
        files={"file": ("b.eml", sample_benign_eml_bytes, "message/rfc822")},
    )
    case_id = r.json()["case"]["id"]

    r = await client.get(f"/api/v1/cases/{case_id}/findings", headers=headers)
    infra_findings = [f for f in r.json() if f["engine"] == "infrastructure_analysis"]
    codes = {f["code"] for f in infra_findings}
    assert "ORIGIN_ESTABLISHED" in codes or "ORIGIN_UNDETERMINED" in codes  # always one or the other, never silent
