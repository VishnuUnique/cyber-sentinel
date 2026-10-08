#!/usr/bin/env python3
"""
Startup script: ensures models and demo data exist before app launch.
Run this before starting the API or dashboard in production.
"""
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(ROOT / "src"))

ANOMALY_MODEL = ROOT / "models" / "anomaly" / "isolation_forest.joblib"
CLASSIFIER_MODEL = ROOT / "models" / "classifier" / "random_forest.joblib"
MIXED_DATA = ROOT / "data" / "samples" / "mixed.jsonl"


def main():
    print("=" * 50)
    print("Cyber Sentinel Startup")
    print("=" * 50)

    if not ANOMALY_MODEL.exists() or not CLASSIFIER_MODEL.exists():
        print("[startup] Models not found. Generating demo data...")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_demo_data.py")],
            cwd=str(ROOT)
        )
        if result.returncode != 0:
            print("[startup] WARNING: generate_demo_data.py failed")

        print("[startup] Training models...")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "train_models.py")],
            cwd=str(ROOT)
        )
        if result.returncode != 0:
            print("[startup] WARNING: train_models.py failed")
    else:
        print("[startup] Models already present. Skipping training.")

    # Ingest sample data into DB if DB is empty
    try:
        from cyber_sentinel.database.database import initialize_database, get_session
        from cyber_sentinel.database.repository import AlertRepository
        initialize_database()
        repo = AlertRepository(session_factory=get_session)
        count = repo.count_alerts()
        if count == 0 and MIXED_DATA.exists():
            print("[startup] Database empty. Ingesting sample data...")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "ingest.py"), "--input", str(MIXED_DATA)],
                cwd=str(ROOT)
            )
            if result.returncode != 0:
                print("[startup] WARNING: ingest.py failed")
            else:
                print("[startup] Sample data ingested successfully.")
        else:
            print(f"[startup] Database has {count} alerts. Skipping ingestion.")
    except Exception as e:
        print(f"[startup] Database check failed: {e}")

    print("[startup] Ready.")


if __name__ == "__main__":
    main()
