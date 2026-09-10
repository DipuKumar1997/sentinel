import pytest


async def _register_and_verify(client, email="alice@acmecorp.com"):
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Analyst",
            "email": email,
            "password": "SuperSecret123!",
            "organization_name": "Acme Corp",
        },
    )
    assert r.status_code == 201
    token = r.json()["message"].split("verification_token=")[-1]
    r = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_account_locks_after_repeated_failed_logins(client):
    await _register_and_verify(client, email="alice@acmecorp.com")

    # 5 wrong-password attempts should each fail with 401...
    for _ in range(5):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@acmecorp.com", "password": "WrongPassword!"},
        )
        assert r.status_code == 401

    # ...and the 6th attempt (even with the CORRECT password) should now
    # be locked out, not merely rejected as a wrong password.
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@acmecorp.com", "password": "SuperSecret123!"},
    )
    assert r.status_code == 423
    assert "locked" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_successful_login_resets_failed_attempt_counter(client):
    await _register_and_verify(client, email="alice@acmecorp.com")

    for _ in range(3):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@acmecorp.com", "password": "WrongPassword!"},
        )
        assert r.status_code == 401

    # A successful login before hitting the lockout threshold should
    # reset the counter...
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@acmecorp.com", "password": "SuperSecret123!"},
    )
    assert r.status_code == 200

    # ...so a further 4 failed attempts alone should NOT yet trigger
    # lockout (would have if the earlier 3 had carried over).
    for _ in range(4):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@acmecorp.com", "password": "WrongPassword!"},
        )
        assert r.status_code == 401

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@acmecorp.com", "password": "SuperSecret123!"},
    )
    assert r.status_code == 200  # not locked out yet -- only 4 consecutive failures


@pytest.mark.asyncio
async def test_login_rate_limit_returns_429_after_threshold(client):
    await _register_and_verify(client, email="alice@acmecorp.com")

    # The login rate limit is 10/minute per client address; issue 11
    # rapid requests (mix of failures is fine -- rate limiting counts
    # requests, not outcomes) and expect the 11th to be throttled.
    statuses = []
    for _ in range(11):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@acmecorp.com", "password": "WrongPassword!"},
        )
        statuses.append(r.status_code)

    assert 429 in statuses
