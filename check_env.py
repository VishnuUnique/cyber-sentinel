"""Environment and syntax checker for Cyber Sentinel."""
import sys
import subprocess
import importlib

print(f"Python: {sys.version}")
print()

# Check required packages
packages = [
    "fastapi", "uvicorn", "pydantic", "pandas", "numpy",
    "sklearn", "joblib", "sqlalchemy", "typer", "yaml",
    "dotenv", "pytest", "httpx", "rich"
]

missing = []
for pkg in packages:
    try:
        m = importlib.import_module(pkg)
        ver = getattr(m, "__version__", "?")
        print(f"  OK  {pkg:<20} {ver}")
    except ImportError:
        print(f"  MISS {pkg}")
        missing.append(pkg)

print()
if missing:
    print(f"Missing: {missing}")
else:
    print("All packages present.")

print()

# Check syntax of key files
import py_compile
files = [
    "src/cyber_sentinel/config/settings.py",
    "src/cyber_sentinel/ingestion/parser.py",
    "src/cyber_sentinel/ingestion/validator.py",
    "src/cyber_sentinel/ingestion/normalizer.py",
    "src/cyber_sentinel/features/extractor.py",
    "src/cyber_sentinel/features/windows.py",
    "src/cyber_sentinel/detection/anomaly.py",
    "src/cyber_sentinel/detection/classifier.py",
    "src/cyber_sentinel/detection/pipeline.py",
    "src/cyber_sentinel/risk/scorer.py",
    "src/cyber_sentinel/risk/evidence.py",
    "src/cyber_sentinel/risk/policy.py",
    "src/cyber_sentinel/database/models.py",
    "src/cyber_sentinel/database/database.py",
    "src/cyber_sentinel/database/repository.py",
    "src/cyber_sentinel/api/main.py",
    "src/cyber_sentinel/api/routes.py",
    "src/cyber_sentinel/cli/main.py",
    "tests/test_ingestion.py",
    "tests/test_features.py",
    "tests/test_detection.py",
    "tests/test_risk.py",
    "tests/test_policy.py",
    "tests/test_api.py",
]

syntax_errors = []
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"  SYNTAX OK  {f}")
    except py_compile.PyCompileError as e:
        print(f"  SYNTAX ERR {f}: {e}")
        syntax_errors.append((f, str(e)))

print()
if syntax_errors:
    print(f"SYNTAX ERRORS: {len(syntax_errors)}")
    for f, e in syntax_errors:
        print(f"  {f}: {e}")
else:
    print("All files syntax OK.")
