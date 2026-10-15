"""Authentication and RBAC tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from jose import jwt

from app.config import get_settings
from app.core.security import create_access_token


def test_register_and_me(client, registered_user, auth_headers):
    me = client.get("/api/auth/me", headers={"Authorization": auth_headers["Authorization"]})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == registered_user["email"]
    assert "user" in body["roles"]
    assert body["is_active"] is True


def test_register_duplicate_email(client, registered_user):
    response = client.post(
        "/api/auth/register",
        json={
            "email": registered_user["email"],
            "password": "AnotherPass!234",
            "full_name": "Dup",
        },
    )
    assert response.status_code == 409


def test_login_invalid_credentials(client, registered_user):
    response = client.post(
        "/api/auth/login",
        json={"email": registered_user["email"], "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_me_requires_auth(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_expired_jwt_rejected(client, registered_user):
    settings = get_settings()
    # Build an already-expired token.
    login = client.post(
        "/api/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert login.status_code == 200
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    user_id = me.json()["id"]

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "roles": ["user"],
        "tv": 0,
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int((now - timedelta(hours=1)).timestamp()),
        "type": "access",
    }
    expired = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_demo_admin_seed_and_rbac(client):
    settings = get_settings()
    login = client.post(
        "/api/auth/login",
        json={
            "email": settings.demo_admin_email,
            "password": settings.demo_admin_password,
        },
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    overview = client.get(
        "/api/admin/sessions/overview",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert overview.status_code == 200
    assert {"total", "active", "revoked"} <= set(overview.json().keys())

    # Ordinary user cannot access admin overview.
    user_login = client.post(
        "/api/auth/login",
        json={
            "email": settings.demo_user_email,
            "password": settings.demo_user_password,
        },
    )
    assert user_login.status_code == 200
    forbidden = client.get(
        "/api/admin/sessions/overview",
        headers={"Authorization": f"Bearer {user_login.json()['access_token']}"},
    )
    assert forbidden.status_code == 403


def test_token_version_mismatch_rejected(client, registered_user, auth_headers):
    settings = get_settings()
    me = client.get("/api/auth/me", headers={"Authorization": auth_headers["Authorization"]})
    user_id = me.json()["id"]
    bad = create_access_token(
        subject=str(user_id),
        roles=["user"],
        token_version=999,
        settings=settings,
    )
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad}"})
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()
