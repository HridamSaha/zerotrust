"""Phase 7 integration tests: continuous risk assessment, policy engine, simulation, and audit logs."""

from __future__ import annotations


def test_post_event_triggers_risk_assessment_and_policy(client, auth_headers):
    session_uid = auth_headers["session_uid"]
    headers = {"Authorization": auth_headers["Authorization"]}

    # Submit a normal event
    event_payload = {
        "event_type": "file_read",
        "resource_name": "public_report.pdf",
        "resource_sensitivity": 1,
        "success": True,
        "payload": {"ip": "192.168.1.100", "action": "read"},
    }
    resp = client.post(
        f"/api/sessions/{session_uid}/events",
        headers=headers,
        json=event_payload,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["event_type"] == "file_read"
    assert data["risk_assessment"] is not None
    assert data["risk_assessment"]["decision"] in {"allow", "allow_limited"}
    assert 0.0 <= data["risk_assessment"]["risk_score"] <= 100.0


def test_session_risk_history_and_events(client, auth_headers):
    session_uid = auth_headers["session_uid"]
    headers = {"Authorization": auth_headers["Authorization"]}

    # Submit multiple events
    for i in range(3):
        client.post(
            f"/api/sessions/{session_uid}/events",
            headers=headers,
            json={
                "event_type": "api_call",
                "resource_name": f"resource_{i}",
                "resource_sensitivity": 2,
                "success": True,
            },
        )

    # Query risk summary
    risk_resp = client.get(f"/api/sessions/{session_uid}/risk", headers=headers)
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert risk_data["session_uid"] == session_uid
    assert len(risk_data["history"]) >= 3

    # Query events list
    events_resp = client.get(f"/api/sessions/{session_uid}/events", headers=headers)
    assert events_resp.status_code == 200
    events_data = events_resp.json()
    assert len(events_data["items"]) >= 3


def test_suspicious_activity_triggers_escalation(client, auth_headers):
    session_uid = auth_headers["session_uid"]
    headers = {"Authorization": auth_headers["Authorization"]}

    # Submit series of high-risk / anomalous events (failures + high sensitivity + unverified context)
    for _ in range(5):
        resp = client.post(
            f"/api/sessions/{session_uid}/events",
            headers=headers,
            json={
                "event_type": "auth_failure",
                "resource_name": "classified_financial_records",
                "resource_sensitivity": 5,
                "success": False,
                "payload": {"unusual_context": True, "device_trusted": False},
            },
        )
        assert resp.status_code == 201

    # Check updated session status
    sess_resp = client.get(f"/api/sessions/{session_uid}", headers=headers)
    assert sess_resp.status_code == 200
    sess = sess_resp.json()
    # Risk score should have elevated above low or session restricted/revoked
    assert sess["current_risk_score"] > 0 or sess["status"] in {"restricted", "step_up_required", "revoked"}


def test_simulation_endpoint(client, auth_headers):
    session_uid = auth_headers["session_uid"]
    headers = {"Authorization": auth_headers["Authorization"]}

    sim_resp = client.post(
        "/api/sessions/simulate",
        headers=headers,
        json={
            "session_uid": session_uid,
            "anomaly_type": "credential_stuffing",
            "event_count": 4,
        },
    )
    assert sim_resp.status_code == 200, sim_resp.text
    sim_data = sim_resp.json()
    assert sim_data["session_uid"] == session_uid
    assert sim_data["events_simulated"] == 4
    assert len(sim_data["assessments"]) == 4


def test_audit_logs_recorded(client):
    # Admin login for audit logs endpoint
    admin_login = client.post(
        "/api/auth/login",
        json={"email": "admin@zerotrust.demo", "password": "AdminDemo!234"},
    )
    assert admin_login.status_code == 200
    token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    audit_resp = client.get("/api/audit-logs?limit=50", headers=headers)
    assert audit_resp.status_code == 200
    data = audit_resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
