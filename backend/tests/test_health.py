"""Health endpoint smoke tests."""


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert "name" in body
    assert body["health"] == "/api/health"


def test_health_endpoint_shape(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["database"] in {"up", "down"}
    assert "app" in body
    assert "version" in body
    assert "environment" in body
