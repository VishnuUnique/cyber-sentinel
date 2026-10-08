"""
Streamlit Cloud entry point for Cyber Sentinel Dashboard.

This file must live at the repo root for Streamlit Community Cloud deployment.
It auto-generates demo data and trains models on first run if needed.
"""
import sys
import os
import subprocess
from pathlib import Path

# Add src/ to Python path
_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(_ROOT / "src"))

# Auto-bootstrap: generate data + train models if not present
_ANOMALY_MODEL = _ROOT / "models" / "anomaly" / "isolation_forest.joblib"
_CLASSIFIER_MODEL = _ROOT / "models" / "classifier" / "random_forest.joblib"

if not _ANOMALY_MODEL.exists() or not _CLASSIFIER_MODEL.exists():
    import streamlit as st
    with st.spinner("🔧 First run: generating demo data and training models (takes ~30s)..."):
        subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "generate_demo_data.py")],
            cwd=str(_ROOT), capture_output=True
        )
        subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "train_models.py")],
            cwd=str(_ROOT), capture_output=True
        )

    # Also run ingestion so the DB has data to display
    _mixed = _ROOT / "data" / "samples" / "mixed.jsonl"
    if _mixed.exists():
        subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "ingest.py"), "--input", str(_mixed)],
            cwd=str(_ROOT), capture_output=True
        )

# Now run the actual dashboard app
_dash = _ROOT / "src" / "cyber_sentinel" / "dashboard" / "app.py"
with open(_dash) as _f:
    exec(compile(_f.read(), str(_dash), "exec"))
