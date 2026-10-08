#!/usr/bin/env python3
"""
Train Cyber Sentinel anomaly and classification models on synthetic data.

WARNING: Trained on SYNTHETIC data. Results do not represent real-world performance.
"""

import csv
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT / "src"))

import numpy as np

from cyber_sentinel.config.settings import Settings
from cyber_sentinel.detection.anomaly import IsolationForestDetector
from cyber_sentinel.detection.classifier import RandomForestThreatClassifier
from cyber_sentinel.features.extractor import FeatureExtractor, FEATURE_NAMES
from cyber_sentinel.features.windows import SlidingWindowBuffer
from cyber_sentinel.ingestion.normalizer import RecordNormalizer
from cyber_sentinel.ingestion.validator import RecordValidator


def load_training_data(cfg):
    """Load and return (records, labels) from training data files."""
    train_data = _ROOT / "data" / "training" / "training_data.jsonl"
    train_labels = _ROOT / "data" / "training" / "training_labels.csv"

    if not train_data.exists() or not train_labels.exists():
        print("Training data not found. Run generate_demo_data.py first.")
        sys.exit(1)

    # Load records
    records_raw = []
    with open(train_data, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records_raw.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    # Load labels
    labels_list = []
    with open(train_labels, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels_list.append(row["label"])

    print(f"Loaded {len(records_raw)} records, {len(labels_list)} labels")
    return records_raw, labels_list


def extract_features_for_record(record_raw, validator, normalizer, extractor):
    """Validate, normalize, and extract features for a single record as its own window."""
    validated, errors = validator.validate(record_raw)
    if validated.get("source_ip") is None:
        return None
    normalized = normalizer.normalize(validated)
    features = extractor.extract([normalized], window_seconds=60)
    return extractor.to_vector(features)


def main():
    print("=" * 60)
    print("CYBER SENTINEL MODEL TRAINING")
    print("=" * 60)
    print()

    cfg = Settings()
    validator = RecordValidator()
    normalizer = RecordNormalizer()
    extractor = FeatureExtractor()

    records_raw, labels_list = load_training_data(cfg)

    # Make sure records and labels align
    min_len = min(len(records_raw), len(labels_list))
    records_raw = records_raw[:min_len]
    labels_list = labels_list[:min_len]

    # Extract features for each record
    print("Extracting features...")
    X_list = []
    y_list = []
    skipped = 0

    for i, (rec, label) in enumerate(zip(records_raw, labels_list)):
        fv = extract_features_for_record(rec, validator, normalizer, extractor)
        if fv is None:
            skipped += 1
            continue
        X_list.append(fv)
        y_list.append(label)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list)

    print(f"Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")
    print(f"Skipped (invalid): {skipped}")
    print()

    # Samples per class
    from collections import Counter
    class_counts = Counter(y_list)
    print(f"{'Class':<25} {'Samples':>8}")
    print("-" * 35)
    for cls, cnt in sorted(class_counts.items()):
        print(f"  {cls:<23} {cnt:>8}")
    print()

    # ── Train Isolation Forest ────────────────────────────────────────────────
    print("Training IsolationForest anomaly detector...")
    anomaly_detector = IsolationForestDetector(
        config={
            "contamination": cfg.anomaly.contamination,
            "random_state": cfg.anomaly.random_state,
            "model_version": cfg.anomaly.model_version,
        }
    )
    anomaly_detector.train(X)

    anomaly_path = cfg.get_anomaly_model_path()
    anomaly_path.parent.mkdir(parents=True, exist_ok=True)
    anomaly_detector.save(str(anomaly_path))
    print(f"  Saved: {anomaly_path}")

    # ── Train Random Forest Classifier ───────────────────────────────────────
    print("Training RandomForest threat classifier...")
    classifier = RandomForestThreatClassifier(
        config={
            "n_estimators": cfg.classifier.n_estimators,
            "random_state": cfg.classifier.random_state,
            "model_version": cfg.classifier.model_version,
        }
    )
    classifier.train(X, y, feature_names=FEATURE_NAMES)

    clf_path = cfg.get_classifier_model_path()
    clf_path.parent.mkdir(parents=True, exist_ok=True)
    classifier.save(str(clf_path))
    print(f"  Saved: {clf_path}")

    # ── Quick accuracy check ──────────────────────────────────────────────────
    print("\nTraining accuracy (on training set — optimistic):")
    correct = 0
    for i in range(min(len(X_list), 200)):  # Sample check on first 200
        result = classifier.predict(X_list[i], feature_names=FEATURE_NAMES)
        if result["predicted_class"] == y_list[i]:
            correct += 1
    n_check = min(len(X_list), 200)
    print(f"  {correct}/{n_check} = {correct/n_check*100:.1f}%")

    print()
    print("=" * 60)
    print("WARNING: Trained on SYNTHETIC data.")
    print("Results do NOT represent real-world performance.")
    print("=" * 60)
    print()
    print(f"Anomaly model:    {anomaly_path}")
    print(f"Classifier model: {clf_path}")
    print()
    print("Training complete.")


if __name__ == "__main__":
    main()
