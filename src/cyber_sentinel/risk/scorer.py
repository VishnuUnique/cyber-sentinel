"""Deterministic 0-100 risk scorer."""

from typing import Dict


class RiskScorer:
    """Computes a deterministic 0-100 risk score from model outputs.

    Formula:
        risk = anomaly_score * w1
             + classifier_confidence_score * w2
             + evidence_score * w3

    Where classifier_confidence_score:
        - classification != 'Normal': confidence * 100
        - classification == 'Normal': confidence * 10
    """

    def score(
        self,
        anomaly_score: float,
        classifier_confidence: float,
        classification: str,
        evidence_score: float,
        weights: Dict[str, float],
    ) -> float:
        """Compute the risk score.

        Args:
            anomaly_score: 0-100 anomaly score (higher = more anomalous).
            classifier_confidence: 0-1 classifier confidence in predicted class.
            classification: Predicted class name string.
            evidence_score: 0-100 evidence score from EvidenceEngine.
            weights: Dict with keys anomaly_weight, classifier_weight, evidence_weight.

        Returns:
            Risk score in [0, 100], deterministic.
        """
        w1 = float(weights.get("anomaly_weight", 0.40))
        w2 = float(weights.get("classifier_weight", 0.30))
        w3 = float(weights.get("evidence_weight", 0.30))

        # Classifier confidence score: penalize non-normal classifications more
        if classification != "Normal" and classification != "Unknown":
            clf_score = float(classifier_confidence) * 100.0
        else:
            clf_score = float(classifier_confidence) * 10.0

        risk = (
            float(anomaly_score) * w1
            + clf_score * w2
            + float(evidence_score) * w3
        )

        # Clamp to [0, 100]
        return max(0.0, min(100.0, risk))
