# Cyber Sentinel — Demo Walkthrough

This walkthrough takes you from a fresh clone to a running detection system.

## Prerequisites

- Python 3.11+
- pip

## Step 1: Install Dependencies

```bash
cd cyber-sentinel
pip install -e .
```

Or without the editable install:
```bash
pip install -r requirements.txt
export PYTHONPATH=src   # Linux/Mac
set PYTHONPATH=src      # Windows
```

## Step 2: Generate Synthetic Demo Data

```bash
python scripts/generate_demo_data.py
```

Expected output:
```
==================================================
SYNTHETIC DEMO DATA GENERATION COMPLETE
==================================================
WARNING: This is SYNTHETIC data. Not real-world traffic.

Class                      Count
-----------------------------------
  Brute Force                200
  Data Exfiltration          200
  Lateral Movement           200
  Normal                    1200
  Port Scan                  200
-----------------------------------
  TOTAL                     2000
```

Files created:
- `data/samples/normal.jsonl`
- `data/samples/port_scan.jsonl`
- `data/samples/brute_force.jsonl`
- `data/samples/lateral_movement.jsonl`
- `data/samples/data_exfiltration.jsonl`
- `data/samples/mixed.jsonl`
- `data/training/training_data.jsonl`
- `data/training/training_labels.csv`

## Step 3: Train Models

```bash
python scripts/train_models.py
```

Expected output:
```
Feature matrix: 2000 samples x 24 features
Training IsolationForest anomaly detector...
Training RandomForest threat classifier...
Training complete.

WARNING: Trained on SYNTHETIC data.
Results do NOT represent real-world performance.
```

Models saved to:
- `models/anomaly/isolation_forest.joblib`
- `models/classifier/random_forest.joblib`

## Step 4: Run Detection on Mixed Data

### Via CLI
```bash
python -m cyber_sentinel.cli.main analyze --input data/samples/mixed.jsonl --max-risk 70
```

### Via ingestion script
```bash
python scripts/ingest.py --input data/samples/mixed.jsonl
```

### Via CLI entry point (after pip install -e .)
```bash
cyber-sentinel analyze --input data/samples/mixed.jsonl --max-risk 70
```

Expected: A table of detections with risk scores and bands.

## Step 5: Start the API Server

```bash
uvicorn cyber_sentinel.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Or via CLI:
```bash
cyber-sentinel api --port 8000
```

Test it:
```bash
curl http://localhost:8000/health
curl http://localhost:8000/statistics
```

Browse interactive docs at: http://localhost:8000/docs

## Step 6: Send Telemetry via API

```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      {
        "timestamp": "2026-10-08T10:00:01Z",
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "src_port": 54321,
        "dest_port": 22,
        "protocol": "TCP",
        "bytes": 500,
        "packets": 4,
        "auth_status": "failure",
        "event_type": "authentication"
      }
    ]
  }'
```

## Step 7: Launch the Dashboard

```bash
streamlit run src/cyber_sentinel/dashboard/app.py
```

Or via CLI:
```bash
cyber-sentinel dashboard --port 8501
```

Browse to: http://localhost:8501

You'll see:
- KPI cards: Total Events, Alerts, Malicious, Suspicious, Avg Risk
- Threat distribution pie chart
- Risk histogram
- Alert timeline
- Top source IPs
- Detailed alert table with evidence

## Step 8: Evaluate Models

```bash
python scripts/evaluate_models.py
```

Shows classification report, confusion matrix, FPR/FNR on synthetic test data.

## Step 9: Run Tests

```bash
pytest tests/ -v
```

## Step 10: Query Alerts via CLI

```bash
cyber-sentinel alerts --risk-min 50 --limit 20
```

## Docker (Optional)

```bash
docker-compose up --build
```

- API: http://localhost:8000
- Dashboard: http://localhost:8501

## Key Points to Remember

- All data used in this demo is **synthetic**
- Models trained on synthetic data will not generalize to real networks
- The system architecture is production-ready; swap in real labeled data for real detection
- Policy guardrail: `--max-risk 70` means any alert with risk > 70 causes exit code 1

## Typical Attack Patterns Detected

| Attack | Key Indicators |
|--------|----------------|
| Port Scan | 30-60 unique dest ports in 60s, small packets, high connection rate |
| Brute Force | 10+ failed auth to single dest, high auth_failure_rate |
| Lateral Movement | Multiple internal peers, auth events, lateral ports (445/139/3389) |
| Data Exfiltration | 10MB+ outbound in window, external destination, few distinct flows |
