"""SQLAlchemy ORM models for Cyber Sentinel."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


class AlertRecord(Base):
    """Persisted Alert record in the audit database."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=True)
    classification = Column(String(64), nullable=False, index=True)
    threat_category = Column(String(64), nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_band = Column(String(16), nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False)
    classifier_confidence = Column(Float, nullable=False)
    evidence_features = Column(Text, nullable=True)      # JSON text
    feature_values = Column(Text, nullable=True)         # JSON text
    class_probabilities = Column(Text, nullable=True)    # JSON text
    model_version = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="new", index=True)
    raw_event_reference = Column(Text, nullable=True)    # JSON text
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<AlertRecord id={self.id} alert_id={self.alert_id!r} "
            f"risk={self.risk_score:.1f} class={self.classification!r}>"
        )


class IngestionRecord(Base):
    """Record of an ingestion run."""

    __tablename__ = "ingestion_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(36), unique=True, nullable=False)
    input_source = Column(String(512), nullable=True)
    records_processed = Column(Integer, nullable=False, default=0)
    records_rejected = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<IngestionRecord id={self.id} run_id={self.run_id!r} "
            f"processed={self.records_processed}>"
        )


class RejectedRecord(Base):
    """A rejected telemetry record stored for audit purposes."""

    __tablename__ = "rejected_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    raw_data = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<RejectedRecord id={self.id} error={self.error_message!r}>"
