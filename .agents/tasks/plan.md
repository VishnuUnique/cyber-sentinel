# Implementation Plan — Cyber Sentinel

This plan is decomposed into five sequential FEATs. Each FEAT leaves the codebase in a working, installable state. The FEAT artifact files are the authoritative implementation spec; this plan summarises ordering, rationale, and known hazards.

---

## Architecture Decisions

**src/ layout with setuptools:** `pyproject.toml` uses `[tool.setuptools.packages.find] where=['src']` so `pip install -e .` works and all imports use `cyber_sentinel.*` regardless of working directory. This avoids `sys.path` hacks in application code. Scripts still need a `sys.path.insert(0, 'src')` guard for standalone use before the package is installed.

**FEATURE_NAMES single source of truth:** Defined once as a module-level tuple in `src/cyber_sentinel/features/extractor.py`. Both `train_models.py` and the inference path (`pipeline.py`) import from there. The classifier joblib bundle also saves a copy as `feature_names.joblib` so loading is self-consistent even if the source is modified later.

**Graceful model degradation:** `AnomalyDetector.score()` returns `50.0` and `ThreatClassifier.predict()` returns `('Unknown', 0.5)` when models aren't loaded. This means the full API and CLI work immediately after `pip install` (before training), and all tests run without needing trained models.

**Risk formula:** `risk = anomaly*0.40 + classifier_confidence_score*0.30 + evidence*0.30` where `classifier_confidence_score = confidence*100 if threat!='Normal' else confidence*10`. Clamped `[0, 100]`. Bands: Normal ≤30, Suspicious 31–70, Malicious >70. All arithmetic is deterministic given the same inputs.

**Circular import prevention:** Dependency graph is strictly layered: `utils/config → database → ingestion → features → detection → risk → api/cli/dashboard`. No layer imports from a layer above it.

**Python 3.14 compatibility note:** The host has Python 3.14.7. All pinned deps (scikit-learn 1.4.2, pandas 2.2.2, etc.) must be verified compatible. If any package fails to install, the coder should try the latest compatible version and document it in `findings`. The pyproject.toml `requires-python = ">=3.11"` is correct — 3.14 satisfies this.

---

## FEAT Order and Dependencies

```
FEAT-001  →  FEAT-002  →  FEAT-003  →  FEAT-004  →  FEAT-005
(scaffold)   (ML core)    (scripts)    (API/CLI/UI  (Docker/docs/
                                        + tests)     polish)
```

---

- [ ] 1. **FEAT-001 — Project scaffold, config, utils, database, ingestion**
      Create entire directory tree with `.gitkeep` files. Write `pyproject.toml` (setuptools src/ layout, pinned deps), `requirements.txt`, `.env.example`, `.gitignore`, `LICENSE`, `config/config.yaml`, `config/policy.yaml`. Implement `settings.py` (PyYAML + python-dotenv, Path-based, cached singleton). Implement `utils/logging.py` (RichHandler + rotating file) and `utils/security.py` (IP validation with `ipaddress` module). Implement SQLAlchemy 2.0 database layer (`database.py`, `models.py`, `repository.py`). Implement ingestion pipeline (`parser.py` — JSON/JSONL/CSV/stdin, `validator.py` — IP validation + noise filter, `normalizer.py` — UTC timestamps, type coercion).
      Files: entire `cyber-sentinel/` tree, `src/cyber_sentinel/config/`, `src/cyber_sentinel/utils/`, `src/cyber_sentinel/database/`, `src/cyber_sentinel/ingestion/`
      Verify: `pip install -e .[dev]` succeeds; `pytest tests/test_ingestion.py -v` passes.

- [ ] 2. **FEAT-002 — Feature engineering, ML detection layers, risk engine**
      Depends on FEAT-001. Define `FEATURE_NAMES` (26-element tuple) in `extractor.py`. Implement `SlidingWindowBuffer` (thread-safe deque keyed by source_ip). Implement `FeatureExtractor.extract()` computing all 26 numeric features with divide-by-zero guards. Implement `AnomalyDetector` (IsolationForest + StandardScaler, score normalisation `(0.5 - raw)*100`, graceful `50.0` default). Implement `ThreatClassifier` (RandomForest + LabelEncoder, graceful `('Unknown',0.5)` default). Implement `DetectionPipeline` (orchestrates both layers). Implement `EvidenceGenerator` (feature-level descriptions with actual values). Implement `RiskScorer` (deterministic formula). Implement `PolicyEngine` (loads `policy.yaml`, CLI exit codes).
      Files: `src/cyber_sentinel/features/`, `src/cyber_sentinel/detection/`, `src/cyber_sentinel/risk/`
      Verify: `pytest tests/test_features.py tests/test_detection.py tests/test_risk.py tests/test_policy.py -v` passes.

- [ ] 3. **FEAT-003 — Synthetic data generation and model training scripts**
      Depends on FEAT-001 + FEAT-002. `generate_demo_data.py`: realistic JSONL for 5 classes (Normal 60%, others 10% each), timestamps spread over 1 hour, writes 6 sample files + training data. `train_models.py`: loads training data, groups into windows, extracts features, trains both models, saves joblib files, prints synthetic data disclaimer. `ingest.py`: CLI wrapper for full pipeline. `evaluate_models.py`: 80/20 split, confusion matrix, F1.
      Files: `scripts/generate_demo_data.py`, `scripts/train_models.py`, `scripts/ingest.py`, `scripts/evaluate_models.py`
      Verify: `python scripts/generate_demo_data.py` + `python scripts/train_models.py` complete and model files exist.

- [ ] 4. **FEAT-004 — FastAPI API, Typer CLI, Streamlit dashboard, pytest suite**
      Depends on FEAT-001 + FEAT-002 (FEAT-003 models are optional — tests use graceful degradation). FastAPI: all 12 endpoints with Pydantic v2 request/response models, `get_db()` dependency injection. Typer CLI: all 8 commands. Streamlit dashboard: KPI row, 4 charts, colour-coded alert table, detail expander with risk gauge — all connected to real SQLite DB. Tests: `conftest.py` with in-memory DB fixture + TestClient fixture; `test_ingestion.py`, `test_features.py`, `test_detection.py`, `test_risk.py`, `test_policy.py`, `test_api.py`.
      Files: `src/cyber_sentinel/api/`, `src/cyber_sentinel/cli/`, `src/cyber_sentinel/dashboard/app.py`, `tests/`
      Verify: `pytest tests/ -v` — all tests pass; `python -m cyber_sentinel.cli.main --help` works.

- [ ] 5. **FEAT-005 — Docker support, documentation, integration audit**
      Depends on all prior FEATs. `Dockerfile` (python:3.11-slim, exposes 8000), `docker-compose.yml` (api + dashboard services). `README.md` (all required sections). `docs/architecture.md`, `docs/detection.md`, `docs/api.md`, `docs/demo.md`. Circular import audit. Full end-to-end integration test: generate → train → ingest → alerts → analyze with --max-risk.
      Files: `Dockerfile`, `docker-compose.yml`, `README.md`, `docs/`
      Verify: full import check + `python scripts/generate_demo_data.py && python scripts/train_models.py && python scripts/ingest.py data/samples/mixed.jsonl`; `pytest tests/ -v` all pass.

---

## Known Hazards

1. **Python 3.14 compatibility**: scikit-learn 1.4.2 and numpy 1.26.4 may not have wheels for CPython 3.14. If `pip install` fails, upgrade to the latest compatible versions (scikit-learn>=1.5, numpy>=2.0) and update `requirements.txt` and `pyproject.toml` accordingly.

2. **Circular imports**: The most common trap is `settings.py` importing from `database`, or `database` importing from `detection`. Keep the layering strict. Do all `from cyber_sentinel.X import Y` inside functions (lazy imports) in `api/` and `cli/` if needed to break any cycle.

3. **FEATURE_NAMES ordering**: The classifier joblib saves both the model and the feature name list. At inference, always reorder the feature dict into `FEATURE_NAMES` order before converting to array. Never rely on dict insertion order.

4. **IsolationForest score sign**: `decision_function` returns negative for anomalies. The normalisation `(0.5 - raw_score) * 100` produces high scores (anomalous) for negative raw values and low scores (normal) for positive values. Verify this is correct with a quick sanity check after training.

5. **Windows path separators**: All `Path` operations in Python are fine with forward slashes. Never concatenate paths with `+` and string literals containing backslashes. Use `pathlib.Path` everywhere.

6. **SQLite threading**: `create_engine('sqlite:///...', connect_args={'check_same_thread': False})` is required. Streamlit runs in a different thread than the FastAPI app, so both must use the same engine config.

7. **Streamlit state**: The dashboard uses `st.rerun()` for auto-refresh. Guard with `st.session_state` to avoid infinite rerun loops on startup.

8. **conftest.py test isolation**: The `test_db` fixture uses SQLite `:memory:` with a fresh `create_all`. The `api_client` fixture must override the `get_db` dependency using `app.dependency_overrides[get_db] = lambda: test_db_session`. Clean up `dependency_overrides` after each test.
