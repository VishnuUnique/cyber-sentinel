"""Tests for the policy guardrail."""

import pytest

from cyber_sentinel.risk.policy import PolicyGuardrail


def _make_alert(risk_score: float, classification: str = "Normal"):
    """Create a minimal mock alert object."""
    class MockAlert:
        def __init__(self, risk, cls):
            self.risk_score = risk
            self.classification = cls
            self.alert_id = "test-alert-id"
            self.source_ip = "10.0.0.1"
            self.risk_band = "Malicious" if risk > 70 else ("Suspicious" if risk > 30 else "Normal")
    return MockAlert(risk_score, classification)


class TestPolicyGuardrail:
    def test_below_threshold_exit_0(self):
        """All alerts below threshold should pass with exit code 0."""
        guardrail = PolicyGuardrail(max_risk=70.0)
        alerts = [_make_alert(30.0), _make_alert(50.0), _make_alert(69.9)]
        result = guardrail.evaluate(alerts)
        assert result.passed is True
        assert result.exit_code == 0
        assert len(result.breach_alerts) == 0

    def test_above_threshold_exit_1(self):
        """Any alert above threshold should fail with exit code 1."""
        guardrail = PolicyGuardrail(max_risk=70.0)
        alerts = [_make_alert(50.0), _make_alert(85.0, "Port Scan")]
        result = guardrail.evaluate(alerts)
        assert result.passed is False
        assert result.exit_code == 1
        assert len(result.breach_alerts) == 1

    def test_exact_threshold_passes(self):
        """Alert exactly at threshold should pass (not breach)."""
        guardrail = PolicyGuardrail(max_risk=70.0)
        alerts = [_make_alert(70.0)]
        result = guardrail.evaluate(alerts)
        assert result.passed is True
        assert result.exit_code == 0

    def test_summary_contains_breach_count(self):
        """Summary string should mention number of breaches."""
        guardrail = PolicyGuardrail(max_risk=50.0)
        alerts = [_make_alert(80.0), _make_alert(90.0), _make_alert(30.0)]
        result = guardrail.evaluate(alerts)
        assert "2" in result.summary or "breach" in result.summary.lower()

    def test_empty_alerts_passes(self):
        """Empty alert list should pass policy with exit code 0."""
        guardrail = PolicyGuardrail(max_risk=70.0)
        result = guardrail.evaluate([])
        assert result.passed is True
        assert result.exit_code == 0
        assert result.max_observed_risk == 0.0
