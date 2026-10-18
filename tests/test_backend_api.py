
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from Engine import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        main,
        "DATABASE_PATH",
        tmp_path / "test_bluesentinel.db",
    )

    main.initialize_database()

    with TestClient(main.app) as test_client:
        yield test_client


def test_root_endpoint(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["database"] == "connected"


def test_event_ingestion_and_normalization(client):
    response = client.post(
        "/events",
        json={
            "event": {
                "event_id": "test-event-001",
                "hostname": "test-host",
                "os": "windows",
                "event_type": "process_creation",
                "process": "notepad.exe",
            }
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["event"]["event_id"] == "test-event-001"
    assert data["event"]["host"] == "test-host"
    assert data["event"]["process"] == "notepad.exe"
    assert data["detection_status"] in {"completed", "failed"}


def test_retrieve_events(client):
    client.post(
        "/events",
        json={
            "event": {
                "event_id": "event-retrieval-001",
                "hostname": "host-a",
                "os": "windows",
                "event_type": "process_creation",
            }
        },
    )

    response = client.get("/events")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert (
        response.json()["items"][0]["event"]["host"]
        == "host-a"
    )


def test_reject_invalid_event_payload(client):
    response = client.post(
        "/events",
        json={"event": "not-an-object"},
    )

    assert response.status_code == 422


def test_empty_hunt(client):
    response = client.post("/hunts/run", json={})

    assert response.status_code == 200
    assert response.json() == {
        "events_examined": 0,
        "findings_created": 0,
        "findings": [],
    }


def test_dashboard_statistics(client):
    client.post(
        "/events",
        json={
            "event": {
                "event_id": "stats-event-001",
                "hostname": "stats-host",
                "os": "windows",
                "event_type": "process_creation",
            }
        },
    )

    response = client.get("/stats")

    assert response.status_code == 200

    data = response.json()

    assert data["events"] == 1
    assert "alerts" in data
    assert "findings" in data
    assert "high_critical_alerts" in data


def test_frontend_cors(client):
    response = client.options(
        "/stats",
        headers={
            "Origin": "http://127.0.0.1:5500",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == "http://127.0.0.1:5500"
    )
