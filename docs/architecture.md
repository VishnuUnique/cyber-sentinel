# Cyber Sentinel — Architecture

## System Overview

Cyber Sentinel is an end-to-end cybersecurity sentinel that converts raw network and security telemetry into explainable, auditable, and policy-driven security decisions.

## Architecture Diagram

```
                ┌─────────────────────────┐
                │ Network/Security Input  │
                │ JSON / JSONL / CSV      │
                │ stdin / file / API      │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Telemetry Ingestion      │
                │ Validation + Normalizer  │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Behavioral Feature       │
                │ Engineering              │
                │ Sliding Windows          │
                └────────────┬────────────┘
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
   ┌───────────────────┐          ┌────────────────────┐
   │ Isolation Forest  │          │ Random Forest      │
   │ Anomaly Detection │          │ Threat Classifier  │
   └─────────┬─────────┘          └──────────┬─────────┘
             │                               │
             └───────────────┬───────────────┘
                             ▼
                ┌─────────────────────────┐
                │ Risk Engine             │
                │ 0–100 Risk Score        │
                │ Evidence Generation     │
                └────────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌────────────┐  ┌──────────────┐
        │ SQLite   │  │ REST API   │  │ Dashboard    │
        │ Audit DB │  │ FastAPI    │  │ Streamlit    │
        └──────────┘  └────────────┘  └──────────────┘
                             │
                             ▼
                   ┌──────────────────┐
                   │ Policy Guardrail │
                   │ --max-risk       │
                   │ Exit 0 / Exit 1  │
                   └──────────────────┘
```

## Component Descriptions

### Telemetry Ingestion
- **parser.py**: Parses JSON, JSONL, and CSV formats from files, stdin, or direct strings
- **validator.py**: Validates each field (IPs, ports, timestamps, auth status) without crashing on malformed input
- **normalizer.py**: Converts validated records to typed `NormalizedRecord` dataclass instances

### Behavioral Feature Engineering
- **windows.py**: Thread-safe `SlidingWindowBuffer` maintains records within configurable time windows (30s, 60s, 300s)
- **extractor.py**: Extracts 24 behavioral features including traffic aggregates, destination diversity, authentication patterns, protocol ratios, and behavioral indicators

### Layer 1 — Unsupervised Anomaly Detection
- **anomaly.py**: `IsolationForestDetector` wraps sklearn's Isolation Forest with StandardScaler preprocessing
- Score normalization: `score = clamp((0.5 - raw) / 1.0 * 100, 0, 100)`
- Can be replaced by One-Class SVM without changing the pipeline interface

### Layer 2 — Supervised Threat Classification
- **classifier.py**: `RandomForestThreatClassifier` classifies into 5 classes: Normal, Port Scan, Brute Force, Lateral Movement, Data Exfiltration
- Enforces consistent feature ordering to prevent column mismatch
- Can be replaced by XGBoost without changing the pipeline interface

### Risk Engine
- **scorer.py**: Deterministic 0–100 risk score: `risk = anomaly*w1 + classifier*w2 + evidence*w3`
- **evidence.py**: Generates human-readable evidence from threshold-based rules
- **policy.py**: Evaluates alerts against configurable max-risk threshold; exits 0 or 1

### Persistence
- **models.py**: SQLAlchemy ORM models for alerts, ingestion runs, and rejected records
- **repository.py**: Data access layer with filtering, pagination, and aggregation

### Presentation
- **api/**: FastAPI REST API with Pydantic request/response models
- **dashboard/**: Streamlit operator dashboard with Plotly charts
- **cli/**: Typer-based CLI for all operations

## Data Flow

1. Raw telemetry (JSON/JSONL/CSV) enters via CLI, API, or file
2. Parser extracts records; validator checks fields; normalizer produces typed records
3. Records are added to the sliding window buffer
4. Feature extractor computes 24 behavioral features over the window
5. Isolation Forest produces anomaly score (0–100)
6. Random Forest produces threat class + confidence
7. Risk scorer combines both into a final 0–100 risk score
8. Evidence engine generates human-readable explanations
9. Alert is created and persisted to SQLite
10. Policy guardrail evaluates max risk and exits 0 or 1
