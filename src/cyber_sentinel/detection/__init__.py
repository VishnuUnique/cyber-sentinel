"""Detection package: anomaly detection and threat classification."""
from .anomaly import IsolationForestDetector
from .classifier import RandomForestThreatClassifier
from .pipeline import SentinelPipeline, Alert

__all__ = [
    "IsolationForestDetector",
    "RandomForestThreatClassifier",
    "SentinelPipeline",
    "Alert",
]
