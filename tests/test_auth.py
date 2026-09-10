import pytest


@pytest.mark.asyncio
async def test_register_login_verify_flow(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Analyst",
            "email": "alice@acmecorp.com",
            "password": "SuperSecret123!",
            "organization_name": "Acme Corp",
        },
    )
    assert r.status_code == 201
    body = r.json()
    verification_token = body["message"].split("verification_token=")[-1]

    # Cannot log in before verifying.
    r = await client.post(
        "/api/v1/auth/login", json={"email": "alice@acmecorp.com", "password": "SuperSecret123!"}
    )
    assert r.status_code == 403

    r = await client.post("/api/v1/auth/verify-email", json={"token": verification_token})
    assert r.status_code == 200
    assert r.json()["is_email_verified"] is True

    r = await client.post(
        "/api/v1/auth/login", json={"email": "alice@acmecorp.com", "password": "SuperSecret123!"}
    )
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens and "refresh_token" in tokens

    r = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert r.status_code == 200
    assert r.json()["email"] == "alice@acmecorp.com"
    assert r.json()["role"] == "employee"


@pytest.mark.asyncio
async def test_duplicate_registration_rejected(client):
    payload = {
        "full_name": "Alice Analyst",
        "email": "alice@acmecorp.com",
        "password": "SuperSecret123!",
        "organization_name": "Acme Corp",
    }
    r1 = await client.post("/api/v1/auth/register", json=payload)
    assert r1.status_code == 201
    r2 = await client.post("/api/v1/auth/register", json=payload)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_wrong_password_rejected(client):
    await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Analyst",
            "email": "alice@acmecorp.com",
            "password": "SuperSecret123!",
            "organization_name": "Acme Corp",
        },
    )
    r = await client.post(
        "/api/v1/auth/login", json={"email": "alice@acmecorp.com", "password": "WrongPassword!"}
    )
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(client):
    r = await client.get("/api/v1/cases")
    assert r.status_code == 401
