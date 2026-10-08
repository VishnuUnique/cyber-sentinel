"""Main detection pipeline: orchestrates ingestion → features → detection → risk → alert."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
from pydantic import BaseModel, Field

from cyber_sentinel.config.settings import settings
from cyber_sentinel.detection.anomaly import IsolationForestDetector
from cyber_sentinel.detection.classifier import RandomForestThreatClassifier
from cyber_sentinel.features.extractor import FeatureExtractor, FEATURE_NAMES
from cyber_sentinel.features.windows import SlidingWindowBuffer
from cyber_sentinel.ingestion.normalizer import NormalizedRecord, RecordNormalizer
from cyber_sentinel.ingestion.validator import RecordValidator
from cyber_sentinel.risk.evidence import EvidenceEngine
from cyber_sentinel.risk.scorer import RiskScorer
from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


def _compute_risk_band(risk_score: float) -> str:
    """Compute risk band string from numeric risk score.

    Args:
        risk_score: Risk score 0-100.

    Returns:
        "Normal" (<=30), "Suspicious" (<=70), or "Malicious" (>70).
    """
    if risk_score <= 30:
        return "Normal"
    elif risk_score <= 70:
        return "Suspicious"
    return "Malicious"


class Alert(BaseModel):
    """Alert model representing a detected threat or anomaly."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    classification: str
    threat_category: str
    risk_score: float
    risk_band: str  # Normal / Suspicious / Malicious
    anomaly_score: float
    classifier_confidence: float
    evidence_features: List[Dict[str, Any]] = Field(default_factory=list)
    feature_values: Dict[str, float] = Field(default_factory=dict)
    class_probabilities: Dict[str, float] = Field(default_factory=dict)
    model_version: str = "1.0.0"
    status: str = "new"
    raw_event_reference: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SentinelPipeline:
    """End-to-end detection pipeline.

    Orchestrates: validate → normalize → sliding window → features →
    anomaly detect → classify → score → evidence → Alert.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        db_repo=None,
    ):
        """Initialize the pipeline.

        Args:
            config_path: Optional path to config.yaml (uses global settings if None).
            db_repo: Optional AlertRepository instance for persisting alerts.
        """
        self._cfg = settings
        self._db_repo = db_repo

        self._validator = RecordValidator()
        self._normalizer = RecordNormalizer()
        self._window = SlidingWindowBuffer(window_sizes=self._cfg.feature_windows)
        self._extractor = FeatureExtractor()
        self._scorer = RiskScorer()
        self._evidence_engine = EvidenceEngine(
            thresholds={
                "unique_ports_high": self._cfg.thresholds.unique_ports_high,
                "unique_ports_critical": self._cfg.thresholds.unique_ports_critical,
                "failed_auth_high": self._cfg.thresholds.failed_auth_high,
                "failed_auth_critical": self._cfg.thresholds.failed_auth_critical,
                "bytes_out_high": self._cfg.thresholds.bytes_out_high,
                "bytes_out_critical": self._cfg.thresholds.bytes_out_critical,
                "unique_peers_high": self._cfg.thresholds.unique_peers_high,
                "unique_peers_critical": self._cfg.thresholds.unique_peers_critical,
                "connection_rate_high": self._cfg.thresholds.connection_rate_high,
                "connection_rate_critical": self._cfg.thresholds.connection_rate_critical,
            }
        )

        self._anomaly_detector = IsolationForestDetector(
            config={
                "contamination": self._cfg.anomaly.contamination,
                "random_state": self._cfg.anomaly.random_state,
                "model_version": self._cfg.anomaly.model_version,
            }
        )
        self._classifier = RandomForestThreatClassifier(
            config={
                "n_estimators": self._cfg.classifier.n_estimators,
                "random_state": self._cfg.classifier.random_state,
                "model_version": self._cfg.classifier.model_version,
            }
        )

        self._stats: Dict[str, int] = {
            "records_processed": 0,
            "records_rejected": 0,
            "alerts_generated": 0,
            "noise_filtered": 0,
        }

        self._load_models()

    def _load_models(self) -> None:
        """Try to load pre-trained models from disk."""
        try:
            anomaly_path = self._cfg.get_anomaly_model_path()
            if anomaly_path.exists():
                self._anomaly_detector.load(str(anomaly_path))
                logger.info("Loaded anomaly model from %s", anomaly_path)
        except Exception as exc:
            logger.warning("Could not load anomaly model: %s", exc)

        try:
            classifier_path = self._cfg.get_classifier_model_path()
            if classifier_path.exists():
                self._classifier.load(str(classifier_path))
                logger.info("Loaded classifier model from %s", classifier_path)
        except Exception as exc:
            logger.warning("Could not load classifier model: %s", exc)

    def process(self, record: dict) -> Optional[Alert]:
        """Process a single raw record dict through the full pipeline.

        Args:
            record: Raw telemetry record dict.

        Returns:
            Alert if the record was processed successfully, None on hard error.
        """
        # Validate
        validated, errors = self._validator.validate(record)
        if validated.get("source_ip") is None:
            self._stats["records_rejected"] += 1
            logger.debug("Rejected record: %s", errors)
            if self._db_repo:
                try:
                    self._db_repo.record_rejected(
                        raw_data=str(record),
                        error_message="; ".join(errors),
                    )
                except Exception:
                    pass
            return None

        # Normalize
        normalized = self._normalizer.normalize(validated)

        # Noise filter
        if self._cfg.noise.enabled:
            if normalized.event_type in self._cfg.noise.event_types:
                self._stats["noise_filtered"] += 1
                logger.debug("Noise filtered event_type: %s", normalized.event_type)
                return None

        self._stats["records_processed"] += 1

        # Add to sliding window
        self._window.add(normalized)
        self._window.expire()

        # Extract features from the window
        window_records = self._window.get_window(self._cfg.window_seconds)
        features = self._extractor.extract(window_records, self._cfg.window_seconds)
        feature_vector = np.array(self._extractor.to_vector(features), dtype=np.float64)

        # Anomaly detection
        anomaly_result = self._anomaly_detector.predict(feature_vector)
        anomaly_score = anomaly_result["anomaly_score"]

        # Threat classification
        clf_result = self._classifier.predict(feature_vector, feature_names=FEATURE_NAMES)
        classification = clf_result["predicted_class"]
        confidence = clf_result["confidence"]
        class_probs = clf_result["class_probabilities"]

        # Evidence generation
        evidence_items = self._evidence_engine.generate(
            features=features,
            classification=classification,
            anomaly_score=anomaly_score,
        )
        evidence_score = self._evidence_engine.compute_evidence_score(evidence_items)

        # Risk scoring
        risk_weights = {
            "anomaly_weight": self._cfg.risk.anomaly_weight,
            "classifier_weight": self._cfg.risk.classifier_weight,
            "evidence_weight": self._cfg.risk.evidence_weight,
        }
        risk_score = self._scorer.score(
            anomaly_score=anomaly_score,
            classifier_confidence=confidence,
            classification=classification,
            evidence_score=evidence_score,
            weights=risk_weights,
        )

        risk_band = _compute_risk_band(risk_score)

        # Determine threat category for display
        threat_category = _map_threat_category(classification, anomaly_result["is_anomaly"])

        # Build model version string
        model_version = (
            f"anomaly={self._cfg.anomaly.model_version},"
            f"classifier={self._cfg.classifier.model_version}"
        )

        # Create Alert
        alert = Alert(
            timestamp=normalized.timestamp,
            source_ip=normalized.source_ip,
            dest_ip=normalized.dest_ip,
            classification=classification,
            threat_category=threat_category,
            risk_score=risk_score,
            risk_band=risk_band,
            anomaly_score=anomaly_score,
            classifier_confidence=confidence,
            evidence_features=[
                {
                    "feature_name": e.feature_name,
                    "observed_value": e.observed_value,
                    "threshold_value": e.threshold_value,
                    "description": e.description,
                    "severity": e.severity,
                }
                for e in evidence_items
            ],
            feature_values=features,
            class_probabilities=class_probs,
            model_version=model_version,
            raw_event_reference=record,
        )

        self._stats["alerts_generated"] += 1

        # Persist if repo available
        if self._db_repo:
            try:
                self._db_repo.create_alert(alert)
            except Exception as exc:
                logger.warning("Failed to persist alert: %s", exc)

        return alert

    def process_batch(self, records: List[dict]) -> List[Alert]:
        """Process a batch of raw record dicts.

        Args:
            records: List of raw telemetry record dicts.

        Returns:
            List of generated Alert objects (may be shorter than input).
        """
        alerts: List[Alert] = []
        for record in records:
            try:
                alert = self.process(record)
                if alert is not None:
                    alerts.append(alert)
            except Exception as exc:
                logger.error("Pipeline error processing record: %s", exc)
                self._stats["records_rejected"] += 1
        return alerts

    def get_stats(self) -> Dict[str, int]:
        """Return pipeline processing statistics.

        Returns:
            Dict with processing counts.
        """
        return dict(self._stats)


def _map_threat_category(classification: str, is_anomaly: bool) -> str:
    """Map classification + anomaly flag to a human-readable threat category."""
    category_map = {
        "Normal": "Benign Traffic",
        "Port Scan": "Reconnaissance",
        "Brute Force": "Credential Attack",
        "Lateral Movement": "Internal Threat",
        "Data Exfiltration": "Data Theft",
        "Unknown": "Unknown Threat",
    }
    cat = category_map.get(classification, "Unknown Threat")
    if classification == "Normal" and is_anomaly:
        return "Behavioral Anomaly"
    return cat
