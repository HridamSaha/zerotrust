"""Shared pytest fixtures."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

TEST_DB_PATH = BACKEND_ROOT / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"

import pytest
from fastapi.testclient import TestClient

from app.core.rate_limit import auth_rate_limiter  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.models import audit, ml_meta, session, user  # noqa: F401, E402
from app.main import create_app  # noqa: E402

# Ensure clean schema for tests
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    auth_rate_limiter.reset()
    yield
    auth_rate_limiter.reset()


@pytest.fixture()
def client() -> TestClient:
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def unique_email() -> str:
    return f"test_{uuid.uuid4().hex[:12]}@example.com"


@pytest.fixture()
def registered_user(client: TestClient, unique_email: str) -> dict:
    password = "TestPass!234"
    response = client.post(
        "/api/auth/register",
        json={
            "email": unique_email,
            "password": password,
            "full_name": "Test User",
        },
    )
    assert response.status_code == 201, response.text
    return {"email": unique_email, "password": password, "user": response.json()}


@pytest.fixture()
def auth_headers(client: TestClient, registered_user: dict) -> dict:
    response = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
            "device_id": "test-device-1",
            "device_trusted": True,
            "context_label": "lab",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "Authorization": f"Bearer {body['access_token']}",
        "session_uid": body["session_uid"],
        "access_token": body["access_token"],
    }
