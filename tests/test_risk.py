"""Tests for risk scoring."""

import pytest

from cyber_sentinel.risk.scorer import RiskScorer


_DEFAULT_WEIGHTS = {
    "anomaly_weight": 0.40,
    "classifier_weight": 0.30,
    "evidence_weight": 0.30,
}


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_risk_score_0_to_100(self):
        """Risk score should always be in [0, 100]."""
        for anomaly in [0, 50, 100]:
            for confidence in [0.0, 0.5, 1.0]:
                for cls in ["Normal", "Port Scan", "Brute Force"]:
                    score = self.scorer.score(
                        anomaly_score=anomaly,
                        classifier_confidence=confidence,
                        classification=cls,
                        evidence_score=50.0,
                        weights=_DEFAULT_WEIGHTS,
                    )
                    assert 0.0 <= score <= 100.0, (
                        f"Score out of range: {score} for anomaly={anomaly}, "
                        f"confidence={confidence}, class={cls}"
                    )

    def test_risk_band_normal(self):
        """Low risk score should produce Normal band."""
        from cyber_sentinel.detection.pipeline import _compute_risk_band
        assert _compute_risk_band(0.0) == "Normal"
        assert _compute_risk_band(30.0) == "Normal"

    def test_risk_band_suspicious(self):
        """Mid-range risk score should produce Suspicious band."""
        from cyber_sentinel.detection.pipeline import _compute_risk_band
        assert _compute_risk_band(31.0) == "Suspicious"
        assert _compute_risk_band(70.0) == "Suspicious"

    def test_risk_band_malicious(self):
        """High risk score should produce Malicious band."""
        from cyber_sentinel.detection.pipeline import _compute_risk_band
        assert _compute_risk_band(70.1) == "Malicious"
        assert _compute_risk_band(100.0) == "Malicious"

    def test_deterministic(self):
        """Same inputs must produce identical score on every call."""
        score1 = self.scorer.score(
            anomaly_score=65.0,
            classifier_confidence=0.8,
            classification="Port Scan",
            evidence_score=40.0,
            weights=_DEFAULT_WEIGHTS,
        )
        score2 = self.scorer.score(
            anomaly_score=65.0,
            classifier_confidence=0.8,
            classification="Port Scan",
            evidence_score=40.0,
            weights=_DEFAULT_WEIGHTS,
        )
        assert score1 == score2

    def test_weights_apply_correctly(self):
        """Anomaly-only weight should produce anomaly_score * w1 when others are 0."""
        # With classifier="Normal" and evidence=0, only anomaly contributes meaningfully
        # Normal class: clf_score = confidence * 10
        score = self.scorer.score(
            anomaly_score=100.0,
            classifier_confidence=0.0,
            classification="Normal",
            evidence_score=0.0,
            weights={"anomaly_weight": 1.0, "classifier_weight": 0.0, "evidence_weight": 0.0},
        )
        assert score == pytest.approx(100.0, abs=0.01)
