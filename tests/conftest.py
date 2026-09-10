import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_run.db")
os.environ.setdefault("EVIDENCE_STORAGE_PATH", "/tmp/sentinelmail_test_evidence")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import shutil
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.base_class import Base
from app.db.session import AsyncSessionLocal, engine
from app.main import app
from app.models import *  # noqa: F401,F403
from app.core.limiter import limiter


@pytest_asyncio.fixture(autouse=True)
def _reset_rate_limiter():
    """The rate limiter's in-memory storage is a module-level singleton
    (see app/core/limiter.py) shared across the whole test session; reset
    it before each test so per-test request counts don't leak into the
    next test's rate-limit budget.
    """
    limiter.reset()
    yield


@pytest_asyncio.fixture(autouse=True)
async def _fresh_database():
    """Creates all tables before each test and drops them after, so tests
    are isolated even though we use a single in-memory-per-connection
    engine configured at import time.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True)
def _evidence_dir():
    path = Path(os.environ["EVIDENCE_STORAGE_PATH"])
    path.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(path, ignore_errors=True)


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_phish_eml_bytes() -> bytes:
    fixture_path = Path(__file__).parent / "fixtures" / "sample_phish.eml"
    return fixture_path.read_bytes()


@pytest.fixture
def sample_benign_eml_bytes() -> bytes:
    fixture_path = Path(__file__).parent / "fixtures" / "sample_benign.eml"
    return fixture_path.read_bytes()
