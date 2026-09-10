import pytest


async def _register_verify_login_admin(client, email="alice@acmecorp.com", organization_name="Acme Corp"):
    """The first registrant of a new org becomes org_admin automatically
    (see auth_service.py) -- exactly the role needed to manage API keys.
    """
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Admin",
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
async def test_first_registrant_of_new_org_becomes_admin(client):
    token = await _register_verify_login_admin(client)
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.json()["role"] == "org_admin"


@pytest.mark.asyncio
async def test_employee_cannot_create_api_key(client):
    admin_token = await _register_verify_login_admin(client, email="admin@acmecorp.com")

    # A second person registering for the SAME (already-existing) org
    # gets the baseline employee role, not admin.
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Bob Employee", "email": "bob@acmecorp.com",
            "password": "SuperSecret123!", "organization_name": "Acme Corp",
        },
    )
    assert r.status_code == 201
    token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": token})
    r = await client.post("/api/v1/auth/login", json={"email": "bob@acmecorp.com", "password": "SuperSecret123!"})
    employee_token = r.json()["access_token"]

    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {employee_token}"})
    assert r.json()["role"] == "employee"

    r = await client.post(
        "/api/v1/api-keys", headers={"Authorization": f"Bearer {employee_token}"},
        json={"name": "should fail"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_create_and_use_api_key_for_ingestion(client, sample_phish_eml_bytes):
    admin_token = await _register_verify_login_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post("/api/v1/api-keys", headers=headers, json={"name": "SOC mail gateway"})
    assert r.status_code == 201
    body = r.json()
    assert body["raw_key"].startswith("sm_live_")
    raw_key = body["raw_key"]

    # Submit an email using ONLY the API key -- no JWT/Authorization header.
    files = {"file": ("phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers={"X-API-Key": raw_key}, files=files)
    assert r.status_code == 201, r.text
    case_id = r.json()["case"]["id"]

    # The admin (same org) can see the case created via the API key.
    r = await client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert r.status_code == 200

    # Listing keys shows it, without ever exposing the raw key again.
    r = await client.get("/api/v1/api-keys", headers=headers)
    assert r.status_code == 200
    keys = r.json()
    assert len(keys) == 1
    assert "raw_key" not in keys[0]
    assert keys[0]["key_prefix"].startswith("sm_live_")


@pytest.mark.asyncio
async def test_invalid_api_key_rejected(client, sample_phish_eml_bytes):
    files = {"file": ("phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post(
        "/api/v1/ingestion/eml", headers={"X-API-Key": "sm_live_totally_made_up"}, files=files
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_revoked_api_key_rejected(client, sample_phish_eml_bytes):
    admin_token = await _register_verify_login_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post("/api/v1/api-keys", headers=headers, json={"name": "temp key"})
    key_id = r.json()["id"]
    raw_key = r.json()["raw_key"]

    r = await client.delete(f"/api/v1/api-keys/{key_id}", headers=headers)
    assert r.status_code == 204

    files = {"file": ("phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers={"X-API-Key": raw_key}, files=files)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_key_cases_are_tenant_isolated(client, sample_phish_eml_bytes):
    admin_a_token = await _register_verify_login_admin(client, email="admin@acmecorp.com", organization_name="Acme Corp")
    r = await client.post(
        "/api/v1/api-keys", headers={"Authorization": f"Bearer {admin_a_token}"}, json={"name": "key A"}
    )
    raw_key_a = r.json()["raw_key"]

    files = {"file": ("phish.eml", sample_phish_eml_bytes, "message/rfc822")}
    r = await client.post("/api/v1/ingestion/eml", headers={"X-API-Key": raw_key_a}, files=files)
    case_id = r.json()["case"]["id"]

    admin_b_token = await _register_verify_login_admin(client, email="admin@othercorp.com", organization_name="Other Corp")
    r = await client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {admin_b_token}"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_admin_can_promote_employee_role(client):
    admin_token = await _register_verify_login_admin(client, email="admin@acmecorp.com")

    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Bob Employee", "email": "bob@acmecorp.com",
            "password": "SuperSecret123!", "organization_name": "Acme Corp",
        },
    )
    token = r.json()["message"].split("verification_token=")[-1]
    await client.post("/api/v1/auth/verify-email", json={"token": token})

    r = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    users = r.json()
    bob = next(u for u in users if u["email"] == "bob@acmecorp.com")
    assert bob["role"] == "employee"

    r = await client.patch(
        f"/api/v1/users/{bob['id']}/role",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "security_analyst"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "security_analyst"
