"""Alert repository: database access layer."""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from cyber_sentinel.database.models import AlertRecord, RejectedRecord
from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


class AlertRepository:
    """Provides CRUD and query operations for AlertRecord and related tables."""

    def __init__(self, session_factory: Callable[..., Session]):
        """Initialize with a session factory or context manager.

        Args:
            session_factory: Callable that returns a Session context manager
                             or plain Session.
        """
        self._session_factory = session_factory

    def _get_session(self):
        """Get a session using the factory."""
        return self._session_factory()

    def create_alert(self, alert: Any) -> AlertRecord:
        """Persist an Alert to the database.

        Args:
            alert: Alert pydantic model instance.

        Returns:
            The created AlertRecord ORM object.
        """
        with self._get_session() as session:
            record = AlertRecord(
                alert_id=str(alert.alert_id),
                timestamp=_ensure_naive(alert.timestamp),
                source_ip=alert.source_ip,
                dest_ip=alert.dest_ip,
                classification=alert.classification,
                threat_category=alert.threat_category,
                risk_score=float(alert.risk_score),
                risk_band=alert.risk_band,
                anomaly_score=float(alert.anomaly_score),
                classifier_confidence=float(alert.classifier_confidence),
                evidence_features=json.dumps(alert.evidence_features),
                feature_values=json.dumps(alert.feature_values),
                class_probabilities=json.dumps(alert.class_probabilities),
                model_version=alert.model_version,
                status=alert.status,
                raw_event_reference=json.dumps(alert.raw_event_reference)
                if alert.raw_event_reference else None,
                created_at=_ensure_naive(alert.created_at),
            )
            session.add(record)
            session.flush()
            session.refresh(record)
            return record

    def get_alert(self, alert_id: str) -> Optional[AlertRecord]:
        """Get a single AlertRecord by alert_id.

        Args:
            alert_id: UUID string of the alert.

        Returns:
            AlertRecord or None if not found.
        """
        with self._get_session() as session:
            return (
                session.query(AlertRecord)
                .filter(AlertRecord.alert_id == alert_id)
                .first()
            )

    def list_alerts(
        self,
        skip: int = 0,
        limit: int = 100,
        risk_min: Optional[float] = None,
        status: Optional[str] = None,
        threat_category: Optional[str] = None,
    ) -> List[AlertRecord]:
        """List alerts with optional filters.

        Args:
            skip: Number of records to skip (for pagination).
            limit: Maximum records to return.
            risk_min: Minimum risk score filter.
            status: Status filter (e.g., "new", "acknowledged").
            threat_category: Threat category filter.

        Returns:
            List of AlertRecord instances.
        """
        with self._get_session() as session:
            q = session.query(AlertRecord)
            if risk_min is not None:
                q = q.filter(AlertRecord.risk_score >= risk_min)
            if status:
                q = q.filter(AlertRecord.status == status)
            if threat_category:
                q = q.filter(AlertRecord.threat_category == threat_category)
            return (
                q.order_by(AlertRecord.created_at.desc())
                .offset(skip)
                .limit(limit)
                .all()
            )

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update the status of an alert.

        Args:
            alert_id: UUID string of the alert.
            status: New status string.

        Returns:
            True if updated, False if not found.
        """
        with self._get_session() as session:
            record = (
                session.query(AlertRecord)
                .filter(AlertRecord.alert_id == alert_id)
                .first()
            )
            if record is None:
                return False
            record.status = status
            return True

    def get_statistics(self) -> Dict[str, Any]:
        """Return aggregate statistics from the alerts table.

        Returns:
            Dict with total_alerts, malicious_count, suspicious_count,
            normal_count, avg_risk_score.
        """
        with self._get_session() as session:
            from sqlalchemy import func

            total = session.query(func.count(AlertRecord.id)).scalar() or 0
            malicious = (
                session.query(func.count(AlertRecord.id))
                .filter(AlertRecord.risk_band == "Malicious")
                .scalar()
                or 0
            )
            suspicious = (
                session.query(func.count(AlertRecord.id))
                .filter(AlertRecord.risk_band == "Suspicious")
                .scalar()
                or 0
            )
            normal = (
                session.query(func.count(AlertRecord.id))
                .filter(AlertRecord.risk_band == "Normal")
                .scalar()
                or 0
            )
            avg_risk = (
                session.query(func.avg(AlertRecord.risk_score)).scalar() or 0.0
            )
            return {
                "total_alerts": total,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "normal_count": normal,
                "avg_risk_score": float(avg_risk),
            }

    def get_top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the top source IPs by alert count.

        Args:
            limit: Number of top sources to return.

        Returns:
            List of dicts with source_ip and alert_count.
        """
        with self._get_session() as session:
            from sqlalchemy import func

            rows = (
                session.query(
                    AlertRecord.source_ip,
                    func.count(AlertRecord.id).label("alert_count"),
                )
                .group_by(AlertRecord.source_ip)
                .order_by(func.count(AlertRecord.id).desc())
                .limit(limit)
                .all()
            )
            return [{"source_ip": r.source_ip, "alert_count": r.alert_count} for r in rows]

    def get_threat_distribution(self) -> Dict[str, int]:
        """Return a count of alerts by classification.

        Returns:
            Dict mapping classification label to count.
        """
        with self._get_session() as session:
            from sqlalchemy import func

            rows = (
                session.query(
                    AlertRecord.classification,
                    func.count(AlertRecord.id).label("count"),
                )
                .group_by(AlertRecord.classification)
                .all()
            )
            return {r.classification: r.count for r in rows}

    def get_risk_distribution(self) -> List[Dict[str, Any]]:
        """Return risk score distribution in buckets of 10.

        Returns:
            List of dicts with bucket and count.
        """
        with self._get_session() as session:
            rows = session.query(AlertRecord.risk_score).all()
            buckets: Dict[str, int] = {}
            for (score,) in rows:
                bucket = f"{int(score // 10) * 10}-{int(score // 10) * 10 + 10}"
                buckets[bucket] = buckets.get(bucket, 0) + 1
            return [{"bucket": k, "count": v} for k, v in sorted(buckets.items())]

    def record_rejected(self, raw_data: str, error_message: str) -> None:
        """Record a rejected telemetry record.

        Args:
            raw_data: Raw data string that was rejected.
            error_message: Description of why it was rejected.
        """
        with self._get_session() as session:
            record = RejectedRecord(
                raw_data=raw_data[:2000] if raw_data else None,
                error_message=error_message[:500] if error_message else None,
                created_at=datetime.now(timezone.utc),
                timestamp=datetime.now(timezone.utc),
            )
            session.add(record)

    def count_alerts(self) -> int:
        """Return total number of alerts."""
        with self._get_session() as session:
            from sqlalchemy import func
            return session.query(func.count(AlertRecord.id)).scalar() or 0


def _ensure_naive(dt: datetime) -> datetime:
    """Strip timezone info for SQLite compatibility."""
    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt
