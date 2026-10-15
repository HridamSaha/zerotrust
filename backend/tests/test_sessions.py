"""Session lifecycle and revocation tests."""


def test_login_creates_session(client, auth_headers):
    response = client.get(
        "/api/sessions",
        headers={"Authorization": auth_headers["Authorization"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    uids = {item["session_uid"] for item in body["items"]}
    assert auth_headers["session_uid"] in uids


def test_create_list_get_session(client, auth_headers):
    created = client.post(
        "/api/sessions",
        headers={"Authorization": auth_headers["Authorization"]},
        json={"device_id": "device-2", "device_trusted": False, "context_label": "office"},
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    session_uid = payload["session"]["session_uid"]
    new_token = payload["access_token"]

    listed = client.get(
        "/api/sessions",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert listed.status_code == 200
    assert any(item["session_uid"] == session_uid for item in listed.json()["items"])

    detail = client.get(
        f"/api/sessions/{session_uid}",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert detail.status_code == 200
    assert detail.json()["status"] == "active"


def test_protected_ping_and_revocation(client, auth_headers):
    session_uid = auth_headers["session_uid"]
    headers = {"Authorization": auth_headers["Authorization"]}

    ok = client.get(f"/api/sessions/{session_uid}/protected-ping", headers=headers)
    assert ok.status_code == 200
    assert ok.json()["ok"] is True

    revoked = client.post(
        f"/api/sessions/{session_uid}/revoke",
        headers=headers,
        json={"reason": "test_revoke"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["session_token_version"] >= 1

    denied = client.get(f"/api/sessions/{session_uid}/protected-ping", headers=headers)
    assert denied.status_code in {401, 403}


def test_cannot_access_other_users_session(client, registered_user):
    # User A
    login_a = client.post(
        "/api/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    session_a = login_a.json()["session_uid"]

    # User B
    email_b = registered_user["email"].replace("@", "+b@")
    reg_b = client.post(
        "/api/auth/register",
        json={"email": email_b, "password": "OtherPass!234", "full_name": "User B"},
    )
    assert reg_b.status_code == 201
    login_b = client.post(
        "/api/auth/login",
        json={"email": email_b, "password": "OtherPass!234"},
    )
    assert login_b.status_code == 200
    token_b = login_b.json()["access_token"]

    response = client.get(
        f"/api/sessions/{session_a}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert response.status_code == 404
