"""Tests for behavioral feature extraction and sliding windows."""

import time
from datetime import datetime, timezone, timedelta

import pytest

from cyber_sentinel.features.extractor import FeatureExtractor, FEATURE_NAMES
from cyber_sentinel.features.windows import SlidingWindowBuffer
from cyber_sentinel.ingestion.normalizer import NormalizedRecord


def _make_record(
    source_ip="10.0.0.1",
    dest_ip="10.0.0.2",
    dest_port=443,
    protocol="TCP",
    bytes_val=1000.0,
    packets_val=10.0,
    auth_status=None,
    event_type="flow",
    offset_seconds=0,
) -> NormalizedRecord:
    ts = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return NormalizedRecord(
        timestamp=ts,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        bytes=bytes_val,
        packets=packets_val,
        auth_status=auth_status,
        event_type=event_type,
    )


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_feature_vector_correct_length(self):
        """Feature vector must have exactly len(FEATURE_NAMES) elements."""
        records = [_make_record() for _ in range(5)]
        features = self.extractor.extract(records)
        assert len(features) == len(FEATURE_NAMES)
        vec = self.extractor.to_vector(features)
        assert len(vec) == len(FEATURE_NAMES)

    def test_unique_dest_ports_counted(self):
        """unique_dest_ports should count distinct destination ports."""
        records = [
            _make_record(dest_port=80),
            _make_record(dest_port=443),
            _make_record(dest_port=80),  # duplicate
            _make_record(dest_port=8080),
        ]
        features = self.extractor.extract(records)
        assert features["unique_dest_ports"] == 3.0

    def test_failed_auth_count(self):
        """failed_auth_count should count records with auth_status='failure'."""
        records = [
            _make_record(auth_status="failure"),
            _make_record(auth_status="failure"),
            _make_record(auth_status="success"),
            _make_record(auth_status=None),
        ]
        features = self.extractor.extract(records)
        assert features["failed_auth_count"] == 2.0
        assert features["success_auth_count"] == 1.0

    def test_bytes_aggregated(self):
        """total_bytes should sum bytes across all records."""
        records = [
            _make_record(bytes_val=1000.0),
            _make_record(bytes_val=2000.0),
            _make_record(bytes_val=500.0),
        ]
        features = self.extractor.extract(records)
        assert features["total_bytes"] == 3500.0

    def test_sliding_window_expires(self):
        """Records older than the window should be expired."""
        buf = SlidingWindowBuffer(window_sizes=[5])  # 5-second window
        # Add old record (10 seconds ago)
        old_record = _make_record(offset_seconds=10)
        buf.add(old_record)
        # Add recent record
        recent_record = _make_record(offset_seconds=1)
        buf.add(recent_record)

        removed = buf.expire()
        assert removed >= 1

        window = buf.get_window(5)
        assert old_record not in window
        assert recent_record in window

    def test_feature_names_consistent(self):
        """Feature dict keys should match FEATURE_NAMES exactly."""
        records = [_make_record()]
        features = self.extractor.extract(records)
        assert set(features.keys()) == set(FEATURE_NAMES)

    def test_empty_window_zero_features(self):
        """Empty record list should produce all-zero features."""
        features = self.extractor.extract([])
        for name in FEATURE_NAMES:
            assert features[name] == 0.0, f"{name} should be 0.0 for empty window"

    def test_connection_rate_per_minute(self):
        """connection_rate should be events per minute based on window_seconds."""
        records = [_make_record() for _ in range(30)]
        features = self.extractor.extract(records, window_seconds=60)
        # 30 events in 60 seconds = 30 events/min
        assert features["connection_rate"] == pytest.approx(30.0, rel=0.01)
