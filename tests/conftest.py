"""Shared test fixtures for Cyber Sentinel test suite."""

import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure src/ is importable
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="session")
def sample_normal_record():
    """Valid normal network flow record."""
    return {
        "timestamp": "2026-10-08T10:00:01Z",
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "src_port": 54321,
        "dest_port": 443,
        "protocol": "TCP",
        "bytes": 1200,
        "packets": 10,
        "auth_status": None,
        "event_type": "flow",
    }


@pytest.fixture(scope="session")
def sample_port_scan_record():
    """Port scan pattern record."""
    return {
        "timestamp": "2026-10-08T10:00:05Z",
        "source_ip": "10.0.0.15",
        "dest_ip": "10.0.0.1",
        "src_port": 60000,
        "dest_port": 22,
        "protocol": "TCP",
        "bytes": 60,
        "packets": 1,
        "auth_status": None,
        "event_type": "flow",
    }


@pytest.fixture(scope="session")
def sample_brute_force_record():
    """Brute force authentication record."""
    return {
        "timestamp": "2026-10-08T10:00:10Z",
        "source_ip": "10.0.0.15",
        "dest_ip": "10.0.0.5",
        "src_port": 50123,
        "dest_port": 22,
        "protocol": "TCP",
        "bytes": 500,
        "packets": 4,
        "auth_status": "failure",
        "event_type": "authentication",
    }


@pytest.fixture(scope="session")
def sample_malformed_record():
    """Record with missing required fields."""
    return {
        "timestamp": "2026-10-08T10:00:20Z",
        # source_ip missing
        "dest_ip": "10.0.0.30",
        "dest_port": 80,
        "event_type": "flow",
    }


@pytest.fixture(scope="session")
def sample_invalid_ip_record():
    """Record with an invalid IP address."""
    return {
        "timestamp": "2026-10-08T10:00:30Z",
        "source_ip": "999.999.999.999",
        "dest_ip": "10.0.0.20",
        "dest_port": 443,
        "event_type": "flow",
    }


@pytest.fixture
def pipeline_fixture():
    """SentinelPipeline without pre-trained models (handles gracefully)."""
    from cyber_sentinel.detection.pipeline import SentinelPipeline
    return SentinelPipeline(db_repo=None)


@pytest.fixture
def db_fixture(tmp_path):
    """Temporary SQLite database for testing."""
    db_path = tmp_path / "test_cyber_sentinel.db"
    db_url = f"sqlite:///{db_path}"

    from cyber_sentinel.database.database import initialize_database, get_session
    initialize_database(db_url=db_url)

    from cyber_sentinel.database.repository import AlertRepository
    from cyber_sentinel.database.database import get_session
    repo = AlertRepository(session_factory=get_session)
    return repo


@pytest.fixture
def api_client():
    """FastAPI TestClient for API tests."""
    from cyber_sentinel.api.main import app
    return TestClient(app)
