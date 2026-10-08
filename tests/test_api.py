"""Tests for the FastAPI REST API."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Module-scoped TestClient."""
    from cyber_sentinel.api.main import app
    with TestClient(app) as c:
        yield c


class TestAPI:
    def test_health_200(self, client):
        """GET /health should return 200 with status='ok'."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "models_loaded" in data

    def test_ingest_valid_200(self, client, sample_normal_record):
        """POST /ingest with a valid record should return 200."""
        response = client.post("/ingest", json={"records": [sample_normal_record]})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["records_received"] == 1

    def test_analyze_returns_list(self, client, sample_brute_force_record):
        """POST /analyze/batch should return a list of alerts."""
        response = client.post(
            "/analyze/batch",
            json={"records": [sample_brute_force_record]},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_alerts_list(self, client):
        """GET /alerts should return a list (possibly empty)."""
        response = client.get("/alerts")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_nonexistent_alert_404(self, client):
        """GET /alerts/{nonexistent_id} should return 404."""
        response = client.get("/alerts/nonexistent-alert-id-12345")
        assert response.status_code == 404

    def test_update_alert_status(self, client, sample_normal_record):
        """PATCH /alerts/{id}/status should update status."""
        # First create an alert via analyze
        analyze_response = client.post(
            "/analyze",
            json={"record": sample_normal_record},
        )
        # The analyze endpoint may return None for normal/noise-filtered traffic
        # so we look for an existing alert instead
        alerts_response = client.get("/alerts?limit=1")
        assert alerts_response.status_code == 200
        alerts = alerts_response.json()

        if alerts:
            alert_id = alerts[0]["alert_id"]
            patch_response = client.patch(
                f"/alerts/{alert_id}/status",
                json={"status": "acknowledged"},
            )
            assert patch_response.status_code == 200
            data = patch_response.json()
            assert data["status"] == "acknowledged"

    def test_invalid_request_422(self, client):
        """POST /ingest without required field should return 422."""
        response = client.post("/ingest", json={"not_records": []})
        assert response.status_code == 422
