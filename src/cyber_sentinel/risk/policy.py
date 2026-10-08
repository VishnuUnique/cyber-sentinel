"""Policy guardrail: evaluates risk scores against configurable thresholds."""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""

    passed: bool
    max_observed_risk: float
    breach_alerts: List[Dict[str, Any]]
    summary: str
    exit_code: int  # 0 if passed, 1 if breach


class PolicyGuardrail:
    """Evaluates a batch of alerts against a configurable risk threshold.

    Implements the --max-risk policy: exits 0 if all alerts are below
    the threshold, exits 1 if any alert exceeds it.
    """

    def __init__(self, max_risk: float):
        """Initialize with a risk threshold.

        Args:
            max_risk: Maximum allowed risk score (0-100).
        """
        self.max_risk = float(max_risk)

    def evaluate(self, alerts: List[Any]) -> PolicyResult:
        """Evaluate a list of alerts against the policy threshold.

        Args:
            alerts: List of Alert objects (must have .risk_score attribute).

        Returns:
            PolicyResult with pass/fail status, breach details, and exit code.
        """
        if not alerts:
            return PolicyResult(
                passed=True,
                max_observed_risk=0.0,
                breach_alerts=[],
                summary="No alerts to evaluate. Policy passed.",
                exit_code=0,
            )

        breach_alerts = []
        max_risk_seen = 0.0

        for alert in alerts:
            risk = float(getattr(alert, "risk_score", 0.0))
            if risk > max_risk_seen:
                max_risk_seen = risk
            if risk > self.max_risk:
                breach_alerts.append({
                    "alert_id": getattr(alert, "alert_id", "unknown"),
                    "source_ip": getattr(alert, "source_ip", "unknown"),
                    "risk_score": risk,
                    "classification": getattr(alert, "classification", "unknown"),
                    "risk_band": getattr(alert, "risk_band", "unknown"),
                })

        passed = len(breach_alerts) == 0
        exit_code = 0 if passed else 1

        if passed:
            summary = (
                f"Policy PASSED: {len(alerts)} alert(s) evaluated, "
                f"max risk {max_risk_seen:.1f} <= threshold {self.max_risk:.1f}."
            )
        else:
            summary = (
                f"Policy BREACH: {len(breach_alerts)}/{len(alerts)} alert(s) exceeded "
                f"threshold {self.max_risk:.1f} (max observed: {max_risk_seen:.1f})."
            )
            logger.warning(summary)

        return PolicyResult(
            passed=passed,
            max_observed_risk=max_risk_seen,
            breach_alerts=breach_alerts,
            summary=summary,
            exit_code=exit_code,
        )
