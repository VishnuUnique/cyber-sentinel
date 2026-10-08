"""Tests for anomaly detection, threat classification, and the pipeline."""

import tempfile
from pathlib import Path

import numpy as np
import pytest

from cyber_sentinel.detection.anomaly import IsolationForestDetector
from cyber_sentinel.detection.classifier import RandomForestThreatClassifier
from cyber_sentinel.features.extractor import FEATURE_NAMES


def _make_X(n_samples=100, n_features=None):
    """Create random feature matrix for testing."""
    if n_features is None:
        n_features = len(FEATURE_NAMES)
    rng = np.random.default_rng(42)
    return rng.random((n_samples, n_features)).astype(np.float64)


def _make_y(n_samples=100):
    """Create balanced label array for testing."""
    classes = ["Normal", "Port Scan", "Brute Force", "Lateral Movement", "Data Exfiltration"]
    return np.array([classes[i % len(classes)] for i in range(n_samples)])


class TestAnomalyDetector:
    def test_anomaly_trains(self):
        """Anomaly detector should train without error."""
        detector = IsolationForestDetector({"contamination": 0.1, "random_state": 42})
        X = _make_X(200)
        detector.train(X)
        assert detector.is_trained

    def test_anomaly_score_range(self):
        """Anomaly score should be in [0, 100]."""
        detector = IsolationForestDetector({"contamination": 0.1, "random_state": 42})
        X = _make_X(200)
        detector.train(X)
        result = detector.predict(X[0])
        assert 0.0 <= result["anomaly_score"] <= 100.0
        assert isinstance(result["is_anomaly"], bool)

    def test_anomaly_saves_loads(self, tmp_path):
        """Model should save to disk and reload correctly."""
        detector = IsolationForestDetector({"contamination": 0.1, "random_state": 42})
        X = _make_X(100)
        detector.train(X)

        model_path = tmp_path / "test_model.joblib"
        detector.save(str(model_path))
        assert model_path.exists()

        # Load fresh instance
        detector2 = IsolationForestDetector()
        detector2.load(str(model_path))
        assert detector2.is_trained

        result = detector2.predict(X[0])
        assert 0.0 <= result["anomaly_score"] <= 100.0


class TestClassifier:
    def test_classifier_trains(self):
        """Classifier should train without error."""
        clf = RandomForestThreatClassifier({"n_estimators": 10, "random_state": 42})
        X = _make_X(100)
        y = _make_y(100)
        clf.train(X, y, feature_names=FEATURE_NAMES)
        assert clf.is_trained

    def test_classifier_all_class_probs(self):
        """Classifier output should include probabilities for all 5 classes."""
        clf = RandomForestThreatClassifier({"n_estimators": 10, "random_state": 42})
        X = _make_X(100)
        y = _make_y(100)
        clf.train(X, y, feature_names=FEATURE_NAMES)
        result = clf.predict(X[0], feature_names=FEATURE_NAMES)
        assert "class_probabilities" in result
        probs = result["class_probabilities"]
        for cls in RandomForestThreatClassifier.CLASSES:
            assert cls in probs, f"Missing class: {cls}"
        assert all(0.0 <= v <= 1.0 for v in probs.values())

    def test_classifier_feature_ordering(self):
        """Classifier must handle reordered feature names without crashing."""
        clf = RandomForestThreatClassifier({"n_estimators": 10, "random_state": 42})
        X = _make_X(100)
        y = _make_y(100)
        clf.train(X, y, feature_names=FEATURE_NAMES)

        # Shuffle feature names and corresponding vector
        shuffled_names = list(reversed(FEATURE_NAMES))
        shuffled_X = X[0][::-1]  # Reverse feature order
        result = clf.predict(shuffled_X, feature_names=shuffled_names)
        assert "predicted_class" in result
        assert result["predicted_class"] in (
            RandomForestThreatClassifier.CLASSES + ["Unknown"]
        )


class TestPipeline:
    def test_pipeline_single_record(self, sample_normal_record):
        """Pipeline should process a single record without crashing."""
        from cyber_sentinel.detection.pipeline import SentinelPipeline
        pipeline = SentinelPipeline(db_repo=None)
        alert = pipeline.process(sample_normal_record)
        # Alert may be None (filtered) or an Alert object
        if alert is not None:
            assert 0.0 <= alert.risk_score <= 100.0
            assert alert.risk_band in {"Normal", "Suspicious", "Malicious"}
            assert alert.source_ip == "10.0.0.10"

    def test_pipeline_batch(self, sample_normal_record, sample_brute_force_record):
        """Pipeline should process a batch of records."""
        from cyber_sentinel.detection.pipeline import SentinelPipeline
        pipeline = SentinelPipeline(db_repo=None)
        records = [sample_normal_record, sample_brute_force_record]
        alerts = pipeline.process_batch(records)
        assert isinstance(alerts, list)
        for alert in alerts:
            assert 0.0 <= alert.risk_score <= 100.0
            assert alert.source_ip is not None
