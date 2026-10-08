# 🛡️ Cyber Sentinel

**Intelligent Cyber Threat and Network Anomaly Detection Sentinel**

An end-to-end cybersecurity system that converts raw network/security telemetry into explainable, auditable, and policy-driven security decisions.

> ⚠️ **Disclaimer**: This project uses **synthetic demo data**. Models trained on this data do not represent real-world threat detection capability. Replace with real labeled network traffic data for production use.

---

## Architecture

```
                ┌─────────────────────────┐
                │ Network/Security Input  │
                │ JSON / JSONL / CSV      │
                │ stdin / file / API      │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │ Telemetry Ingestion      │
                │ Validation + Normalizer  │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │ Behavioral Feature       │
                │ Engineering (24 features)│
                │ Sliding Windows (30/60/300s)│
                └────────────┬────────────┘
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
   ┌───────────────────┐          ┌────────────────────┐
   │ Isolation Forest  │          │ Random Forest      │
   │ Anomaly Detection │          │ Threat Classifier  │
   └─────────┬─────────┘          └──────────┬─────────┘
             └───────────────┬───────────────┘
                             ▼
                ┌─────────────────────────┐
                │ Risk Engine             │
                │ 0–100 Score + Evidence  │
                └────────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌────────────┐  ┌──────────────┐
        │ SQLite   │  │ FastAPI    │  │ Streamlit    │
        │ Audit DB │  │ REST API   │  │ Dashboard    │
        └──────────┘  └────────────┘  └──────────────┘
```

## Quick Start

```bash
# 1. Clone and install
cd cyber-sentinel
pip install -e .

# 2. Generate synthetic demo data
python scripts/generate_demo_data.py

# 3. Train models
python scripts/train_models.py

# 4. Analyze telemetry
cyber-sentinel analyze --input data/samples/mixed.jsonl --max-risk 70

# 5. Start API
cyber-sentinel api --port 8000

# 6. Launch dashboard
cyber-sentinel dashboard --port 8501
```

## Installation

### Requirements
- Python 3.11+
- pip

### Install
```bash
pip install -r requirements.txt
pip install -e .
```

### Environment Setup
```bash
cp .env.example .env
# Edit .env as needed
```

## Usage

### CLI

```bash
# Generate synthetic data
cyber-sentinel generate-data

# Train models
cyber-sentinel train

# Ingest and analyze a file
cyber-sentinel ingest --input data/samples/mixed.jsonl

# Analyze with policy enforcement (exits 1 if any risk > 70)
cyber-sentinel analyze --input data/samples/mixed.jsonl --max-risk 70

# Query database alerts
cyber-sentinel alerts --risk-min 50 --limit 20

# Start API server
cyber-sentinel api --port 8000

# Launch dashboard
cyber-sentinel dashboard --port 8501

# Evaluate model performance
cyber-sentinel evaluate
```

### API

Start the server:
```bash
uvicorn cyber_sentinel.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Key endpoints:
- `GET /health` — system health
- `POST /ingest` — ingest telemetry batch
- `POST /analyze` — analyze single record
- `POST /analyze/batch` — analyze batch
- `GET /alerts` — list alerts (paginated + filtered)
- `GET /statistics` — aggregate statistics

Full API docs: http://localhost:8000/docs

### Dashboard

```bash
streamlit run src/cyber_sentinel/dashboard/app.py
```

Browse to: http://localhost:8501

### Direct Script Usage (no package install)
```bash
# Set PYTHONPATH
export PYTHONPATH=src  # Linux/Mac
$env:PYTHONPATH="src"  # PowerShell

python scripts/generate_demo_data.py
python scripts/train_models.py
python scripts/ingest.py --input data/samples/mixed.jsonl
python scripts/evaluate_models.py
```

## Configuration

### config/config.yaml
- `window_seconds`: Detection window duration
- `anomaly.contamination`: Expected fraction of anomalies
- `risk.anomaly_weight`, `risk.classifier_weight`, `risk.evidence_weight`: Score weights
- `risk.max_risk`: Default policy threshold
- `thresholds.*`: Evidence generation thresholds

### config/policy.yaml
- `policy.max_risk`: Alert threshold
- `policy.block_on_malicious`: Block on malicious classification

### Environment Variables
- `DATABASE_URL`: Override database URL
- `LOG_LEVEL`: Logging level (DEBUG/INFO/WARNING/ERROR)
- `CONFIG_PATH`: Override config file path
- `MAX_RISK`: Override risk threshold

## Threat Classes

| Class | Description | Key Indicators |
|-------|-------------|----------------|
| Normal | Benign traffic | Low port diversity, normal bytes |
| Port Scan | Reconnaissance | 30-60 unique ports/min, tiny packets |
| Brute Force | Credential attacks | High failed auth count, auth_failure_rate > 70% |
| Lateral Movement | Internal spread | Multiple internal peers, lateral ports |
| Data Exfiltration | Data theft | Very high bytes to external IP |

## Testing

```bash
pytest tests/ -v
```

Run specific test files:
```bash
pytest tests/test_ingestion.py -v
pytest tests/test_detection.py -v
pytest tests/test_api.py -v
```

## Docker

```bash
# Build and start all services
docker-compose up --build

# API: http://localhost:8000
# Dashboard: http://localhost:8501
```

## Project Structure

```
cyber-sentinel/
├── README.md
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── config/
│   ├── config.yaml          # Main configuration
│   └── policy.yaml          # Risk policy
├── data/
│   ├── samples/             # Generated sample data
│   └── training/            # Training data + labels
├── models/
│   ├── anomaly/             # Isolation Forest model
│   └── classifier/          # Random Forest model
├── scripts/
│   ├── generate_demo_data.py
│   ├── train_models.py
│   ├── evaluate_models.py
│   └── ingest.py
├── src/cyber_sentinel/
│   ├── api/                 # FastAPI REST API
│   ├── cli/                 # Typer CLI
│   ├── config/              # Settings
│   ├── ingestion/           # Parser, validator, normalizer
│   ├── features/            # Feature extraction + windows
│   ├── detection/           # Anomaly + classifier + pipeline
│   ├── risk/                # Scorer, evidence, policy
│   ├── database/            # SQLAlchemy ORM + repository
│   ├── dashboard/           # Streamlit dashboard
│   └── utils/               # Logging, security
├── tests/                   # pytest test suite
└── docs/                    # Documentation
```

## Synthetic Data Disclaimer

All data generated by `scripts/generate_demo_data.py` is **synthetic and does not represent real network traffic**. The statistical properties are designed to produce reasonable training signal for demonstration purposes, but:

- Detection rates on real traffic may differ significantly
- False positive and false negative rates are not characterized for real networks
- This system requires real labeled network telemetry for production deployment

## License

MIT License — see LICENSE file.
