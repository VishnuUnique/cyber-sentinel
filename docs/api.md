# Cyber Sentinel — API Reference

Base URL: `http://localhost:8000`

Interactive docs: `http://localhost:8000/docs`

## System Endpoints

### GET /health
Check API health and model loading status.

**Response**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "models_loaded": {
    "anomaly_detector": true,
    "threat_classifier": true
  }
}
```

### GET /model/info
Get information about loaded models.

**Response**
```json
{
  "anomaly_model": "IsolationForest",
  "classifier_model": "RandomForest",
  "anomaly_trained": true,
  "classifier_trained": true,
  "anomaly_version": "1.0.0",
  "classifier_version": "1.0.0"
}
```

## Ingestion Endpoints

### POST /ingest
Ingest a batch of raw telemetry records.

**Request**
```json
{
  "records": [
    {
      "timestamp": "2026-10-08T10:00:01Z",
      "source_ip": "10.0.0.10",
      "dest_ip": "10.0.0.20",
      "src_port": 54321,
      "dest_port": 443,
      "protocol": "TCP",
      "bytes": 1200,
      "packets": 10,
      "auth_status": null,
      "event_type": "flow"
    }
  ]
}
```

**Response**
```json
{
  "status": "ok",
  "records_received": 1,
  "records_processed": 1,
  "records_rejected": 0,
  "alerts_generated": 1
}
```

## Detection Endpoints

### POST /analyze
Analyze a single telemetry record.

**Request**
```json
{
  "record": {
    "timestamp": "2026-10-08T10:00:01Z",
    "source_ip": "10.0.0.10",
    "dest_ip": "10.0.0.20",
    "event_type": "flow"
  }
}
```

**Response**: Alert object or `null` for filtered/rejected records.

### POST /analyze/batch
Analyze a batch of records.

**Request**
```json
{
  "records": [ ... ]
}
```

**Response**: Array of Alert objects.

### Alert Object Schema
```json
{
  "alert_id": "uuid4",
  "timestamp": "ISO8601",
  "source_ip": "10.0.0.10",
  "dest_ip": "10.0.0.20",
  "classification": "Port Scan",
  "threat_category": "Reconnaissance",
  "risk_score": 78.3,
  "risk_band": "Malicious",
  "anomaly_score": 82.1,
  "classifier_confidence": 0.91,
  "evidence_features": [
    {
      "feature_name": "unique_dest_ports",
      "observed_value": 45.0,
      "threshold_value": 40.0,
      "description": "Unique destination ports = 45 (critical port diversity)",
      "severity": "critical"
    }
  ],
  "feature_values": { "unique_dest_ports": 45.0, ... },
  "class_probabilities": {
    "Normal": 0.02,
    "Port Scan": 0.91,
    "Brute Force": 0.03,
    "Lateral Movement": 0.02,
    "Data Exfiltration": 0.02
  },
  "model_version": "anomaly=1.0.0,classifier=1.0.0",
  "status": "new",
  "created_at": "ISO8601"
}
```

## Alert Management Endpoints

### GET /alerts
List alerts with optional filtering.

**Query Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| skip | int | Pagination offset (default: 0) |
| limit | int | Max results (default: 100, max: 1000) |
| risk_min | float | Minimum risk score filter |
| status | string | Filter by status |
| threat_category | string | Filter by threat category |

### GET /alerts/{alert_id}
Get a specific alert by ID.

**Response**: Alert object or 404.

### PATCH /alerts/{alert_id}/status
Update alert status.

**Request**
```json
{ "status": "acknowledged" }
```

Valid statuses: `new`, `acknowledged`, `resolved`, `false_positive`

## Analytics Endpoints

### GET /statistics
Get aggregate statistics.

```json
{
  "total_alerts": 150,
  "malicious_count": 23,
  "suspicious_count": 67,
  "normal_count": 60,
  "avg_risk_score": 42.3
}
```

### GET /threats
Alert count by threat classification.

```json
{
  "Normal": 60,
  "Port Scan": 15,
  "Brute Force": 8,
  "Lateral Movement": 12,
  "Data Exfiltration": 3
}
```

### GET /sources/top
Top source IPs by alert count.

**Query Parameters**: `limit` (default: 10)

### GET /risk/distribution
Risk score distribution in 10-point buckets.

```json
[
  {"bucket": "0-10", "count": 12},
  {"bucket": "70-80", "count": 8}
]
```

## Error Responses

| Status | Description |
|--------|-------------|
| 422 | Validation error — missing or invalid request fields |
| 404 | Alert not found |
| 500 | Internal server error |
| 503 | Pipeline not initialized |
