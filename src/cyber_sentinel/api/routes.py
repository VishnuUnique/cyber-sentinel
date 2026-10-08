"""API routes for Cyber Sentinel REST API."""

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


# ── Request / Response models ───────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    models_loaded: Dict[str, bool]


class IngestRequest(BaseModel):
    records: List[Dict[str, Any]] = Field(..., description="List of raw telemetry records")


class IngestResponse(BaseModel):
    status: str
    records_received: int
    records_processed: int
    records_rejected: int
    alerts_generated: int


class AnalyzeRequest(BaseModel):
    record: Dict[str, Any] = Field(..., description="Single raw telemetry record")


class AnalyzeBatchRequest(BaseModel):
    records: List[Dict[str, Any]] = Field(..., description="List of raw telemetry records")


class AlertResponse(BaseModel):
    alert_id: str
    timestamp: str
    source_ip: str
    dest_ip: Optional[str] = None
    classification: str
    threat_category: str
    risk_score: float
    risk_band: str
    anomaly_score: float
    classifier_confidence: float
    evidence_features: List[Dict[str, Any]] = []
    feature_values: Dict[str, float] = {}
    class_probabilities: Dict[str, float] = {}
    model_version: str
    status: str
    created_at: str


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: new|acknowledged|resolved|false_positive")


class StatisticsResponse(BaseModel):
    total_alerts: int
    malicious_count: int
    suspicious_count: int
    normal_count: int
    avg_risk_score: float


class ModelInfoResponse(BaseModel):
    anomaly_model: str
    classifier_model: str
    anomaly_trained: bool
    classifier_trained: bool
    anomaly_version: str
    classifier_version: str


# ── Dependency helpers ────────────────────────────────────────────────────

def get_pipeline():
    """Dependency: get the singleton SentinelPipeline."""
    from cyber_sentinel.api.main import _pipeline
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return _pipeline


def get_repo():
    """Dependency: get the singleton AlertRepository."""
    from cyber_sentinel.api.main import _repo
    return _repo


# ── Routes ────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(pipeline=Depends(get_pipeline)):
    """Check API health and model status."""
    from cyber_sentinel.config.settings import settings
    return HealthResponse(
        status="ok",
        version="1.0.0",
        models_loaded={
            "anomaly_detector": pipeline._anomaly_detector.is_trained,
            "threat_classifier": pipeline._classifier.is_trained,
        },
    )


@router.post("/ingest", response_model=IngestResponse, tags=["Ingestion"])
async def ingest_records(
    request: IngestRequest,
    pipeline=Depends(get_pipeline),
):
    """Ingest a batch of raw telemetry records."""
    before_stats = pipeline.get_stats()
    alerts = pipeline.process_batch(request.records)
    after_stats = pipeline.get_stats()

    processed = after_stats["records_processed"] - before_stats["records_processed"]
    rejected = after_stats["records_rejected"] - before_stats["records_rejected"]
    noise = after_stats["noise_filtered"] - before_stats["noise_filtered"]
    generated = len(alerts)

    return IngestResponse(
        status="ok",
        records_received=len(request.records),
        records_processed=processed + noise,
        records_rejected=rejected,
        alerts_generated=generated,
    )


@router.post("/analyze", response_model=Optional[AlertResponse], tags=["Detection"])
async def analyze_record(
    request: AnalyzeRequest,
    pipeline=Depends(get_pipeline),
):
    """Analyze a single telemetry record and return an alert."""
    alert = pipeline.process(request.record)
    if alert is None:
        return None
    return _alert_to_response(alert)


@router.post("/analyze/batch", response_model=List[AlertResponse], tags=["Detection"])
async def analyze_batch(
    request: AnalyzeBatchRequest,
    pipeline=Depends(get_pipeline),
):
    """Analyze a batch of telemetry records."""
    alerts = pipeline.process_batch(request.records)
    return [_alert_to_response(a) for a in alerts]


@router.get("/alerts", response_model=List[AlertResponse], tags=["Alerts"])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    risk_min: Optional[float] = Query(None, ge=0, le=100),
    status: Optional[str] = Query(None),
    threat_category: Optional[str] = Query(None),
    repo=Depends(get_repo),
):
    """List alerts with optional filtering and pagination."""
    if repo is None:
        return []
    records = repo.list_alerts(
        skip=skip,
        limit=limit,
        risk_min=risk_min,
        status=status,
        threat_category=threat_category,
    )
    return [_db_record_to_response(r) for r in records]


@router.get("/alerts/{alert_id}", response_model=AlertResponse, tags=["Alerts"])
async def get_alert(alert_id: str, repo=Depends(get_repo)):
    """Get a specific alert by ID."""
    if repo is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    record = repo.get_alert(alert_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return _db_record_to_response(record)


@router.patch("/alerts/{alert_id}/status", tags=["Alerts"])
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    repo=Depends(get_repo),
):
    """Update the status of an alert."""
    valid_statuses = {"new", "acknowledged", "resolved", "false_positive"}
    if update.status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Status must be one of {sorted(valid_statuses)}",
        )
    if repo is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    updated = repo.update_alert_status(alert_id, update.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return {"alert_id": alert_id, "status": update.status, "updated": True}


@router.get("/statistics", response_model=StatisticsResponse, tags=["Analytics"])
async def get_statistics(repo=Depends(get_repo)):
    """Get aggregate alert statistics."""
    if repo is None:
        return StatisticsResponse(
            total_alerts=0, malicious_count=0, suspicious_count=0,
            normal_count=0, avg_risk_score=0.0,
        )
    stats = repo.get_statistics()
    return StatisticsResponse(**stats)


@router.get("/threats", tags=["Analytics"])
async def get_threat_distribution(repo=Depends(get_repo)):
    """Get alert count by threat classification."""
    if repo is None:
        return {}
    return repo.get_threat_distribution()


@router.get("/sources/top", tags=["Analytics"])
async def get_top_sources(
    limit: int = Query(10, ge=1, le=100),
    repo=Depends(get_repo),
):
    """Get top source IPs by alert volume."""
    if repo is None:
        return []
    return repo.get_top_sources(limit=limit)


@router.get("/risk/distribution", tags=["Analytics"])
async def get_risk_distribution(repo=Depends(get_repo)):
    """Get risk score distribution in buckets."""
    if repo is None:
        return []
    return repo.get_risk_distribution()


@router.get("/model/info", response_model=ModelInfoResponse, tags=["System"])
async def get_model_info(pipeline=Depends(get_pipeline)):
    """Get information about loaded models."""
    return ModelInfoResponse(
        anomaly_model="IsolationForest",
        classifier_model="RandomForest",
        anomaly_trained=pipeline._anomaly_detector.is_trained,
        classifier_trained=pipeline._classifier.is_trained,
        anomaly_version=pipeline._anomaly_detector.model_version,
        classifier_version=pipeline._classifier.model_version,
    )


# ── Helpers ───────────────────────────────────────────────────────────────

def _alert_to_response(alert) -> AlertResponse:
    """Convert an Alert pydantic model to AlertResponse."""
    return AlertResponse(
        alert_id=alert.alert_id,
        timestamp=alert.timestamp.isoformat(),
        source_ip=alert.source_ip,
        dest_ip=alert.dest_ip,
        classification=alert.classification,
        threat_category=alert.threat_category,
        risk_score=alert.risk_score,
        risk_band=alert.risk_band,
        anomaly_score=alert.anomaly_score,
        classifier_confidence=alert.classifier_confidence,
        evidence_features=alert.evidence_features,
        feature_values=alert.feature_values,
        class_probabilities=alert.class_probabilities,
        model_version=alert.model_version,
        status=alert.status,
        created_at=alert.created_at.isoformat(),
    )


def _db_record_to_response(record) -> AlertResponse:
    """Convert an AlertRecord ORM object to AlertResponse."""
    def _safe_json(text):
        if text is None:
            return {}
        try:
            return json.loads(text)
        except Exception:
            return {}

    def _safe_json_list(text):
        if text is None:
            return []
        try:
            result = json.loads(text)
            return result if isinstance(result, list) else []
        except Exception:
            return []

    ts = record.timestamp
    created = record.created_at
    if hasattr(ts, "isoformat"):
        ts_str = ts.isoformat()
    else:
        ts_str = str(ts)
    if hasattr(created, "isoformat"):
        created_str = created.isoformat()
    else:
        created_str = str(created)

    return AlertResponse(
        alert_id=record.alert_id,
        timestamp=ts_str,
        source_ip=record.source_ip,
        dest_ip=record.dest_ip,
        classification=record.classification,
        threat_category=record.threat_category,
        risk_score=record.risk_score,
        risk_band=record.risk_band,
        anomaly_score=record.anomaly_score,
        classifier_confidence=record.classifier_confidence,
        evidence_features=_safe_json_list(record.evidence_features),
        feature_values=_safe_json(record.feature_values),
        class_probabilities=_safe_json(record.class_probabilities),
        model_version=record.model_version or "",
        status=record.status,
        created_at=created_str,
    )
