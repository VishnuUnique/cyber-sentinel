#!/usr/bin/env python3
"""
Evaluate Cyber Sentinel models on held-out test data (80/20 split).

EVALUATION NOTE: This evaluation uses synthetic/demo telemetry unless a real
labeled dataset is supplied.
"""

import csv
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT / "src"))

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from cyber_sentinel.config.settings import Settings
from cyber_sentinel.detection.anomaly import IsolationForestDetector
from cyber_sentinel.detection.classifier import RandomForestThreatClassifier
from cyber_sentinel.features.extractor import FeatureExtractor, FEATURE_NAMES
from cyber_sentinel.ingestion.normalizer import RecordNormalizer
from cyber_sentinel.ingestion.validator import RecordValidator


def load_data():
    train_data = _ROOT / "data" / "training" / "training_data.jsonl"
    train_labels = _ROOT / "data" / "training" / "training_labels.csv"

    if not train_data.exists():
        print("No training data found. Run generate_demo_data.py first.")
        sys.exit(1)

    records_raw = []
    with open(train_data, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records_raw.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    labels_list = []
    if train_labels.exists():
        with open(train_labels, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                labels_list.append(row["label"])

    return records_raw, labels_list


def extract_features(records_raw, labels_list):
    validator = RecordValidator()
    normalizer = RecordNormalizer()
    extractor = FeatureExtractor()

    X_list, y_list = [], []
    for rec, label in zip(records_raw, labels_list):
        validated, errors = validator.validate(rec)
        if validated.get("source_ip") is None:
            continue
        normalized = normalizer.normalize(validated)
        features = extractor.extract([normalized], window_seconds=60)
        X_list.append(extractor.to_vector(features))
        y_list.append(label)

    return np.array(X_list, dtype=np.float64), np.array(y_list)


def main():
    print("=" * 60)
    print("CYBER SENTINEL MODEL EVALUATION")
    print("=" * 60)
    print("EVALUATION NOTE: Using synthetic/demo telemetry.")
    print("Supply a real labeled dataset for production evaluation.")
    print()

    cfg = Settings()
    records_raw, labels_list = load_data()

    min_len = min(len(records_raw), len(labels_list))
    records_raw = records_raw[:min_len]
    labels_list = labels_list[:min_len]

    print(f"Total samples: {min_len}")
    print("Extracting features...")
    X, y = extract_features(records_raw, labels_list)
    print(f"Feature matrix: {X.shape}")
    print()

    # 80/20 split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Load or train classifier
    clf_path = cfg.get_classifier_model_path()
    classifier = RandomForestThreatClassifier(
        config={
            "n_estimators": cfg.classifier.n_estimators,
            "random_state": cfg.classifier.random_state,
        }
    )

    if clf_path.exists():
        print("Loading trained classifier...")
        classifier.load(str(clf_path))
    else:
        print("No trained model found. Training on 80% split...")
        classifier.train(X_train, y_train, feature_names=FEATURE_NAMES)

    # ── Classifier evaluation ─────────────────────────────────────────────────
    print("Classifier Evaluation (on 20% test split):")
    print("-" * 50)

    y_pred = []
    y_conf = []
    for fv in X_test:
        result = classifier.predict(fv, feature_names=FEATURE_NAMES)
        y_pred.append(result["predicted_class"])
        y_conf.append(result["confidence"])

    classes = sorted(list(set(y_test.tolist() + y_pred)))
    print(classification_report(y_test, y_pred, labels=classes, zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    print("Confusion Matrix:")
    print(f"{'':>20}", end="")
    for c in classes:
        print(f"  {c[:8]:>8}", end="")
    print()
    for i, row in enumerate(cm):
        print(f"{classes[i]:>20}", end="")
        for val in row:
            print(f"  {val:>8}", end="")
        print()
    print()

    # FPR / FNR for Normal class
    if "Normal" in classes:
        normal_idx = classes.index("Normal")
        tp = cm[normal_idx][normal_idx]
        fn = sum(cm[normal_idx]) - tp
        fp = sum(cm[:, normal_idx]) - tp
        tn = cm.sum() - tp - fn - fp
        fpr = fp / max(fp + tn, 1)
        fnr = fn / max(fn + tp, 1)
        print(f"Normal class — FPR: {fpr:.3f}, FNR: {fnr:.3f}")

    # ── Anomaly detection evaluation ──────────────────────────────────────────
    print()
    print("Anomaly Detection Evaluation:")
    print("-" * 50)

    anomaly_path = cfg.get_anomaly_model_path()
    detector = IsolationForestDetector(
        config={"contamination": cfg.anomaly.contamination, "random_state": cfg.anomaly.random_state}
    )

    if anomaly_path.exists():
        print("Loading trained anomaly model...")
        detector.load(str(anomaly_path))
    else:
        print("Training anomaly model on 80% split...")
        detector.train(X_train)

    anomaly_results = [detector.predict(fv) for fv in X_test]
    anomaly_scores = [r["anomaly_score"] for r in anomaly_results]
    anomalies_detected = sum(1 for r in anomaly_results if r["is_anomaly"])

    print(f"Samples tested:        {len(X_test)}")
    print(f"Anomalies flagged:     {anomalies_detected} ({anomalies_detected/len(X_test)*100:.1f}%)")
    print(f"Avg anomaly score:     {sum(anomaly_scores)/len(anomaly_scores):.1f}")
    print(f"Max anomaly score:     {max(anomaly_scores):.1f}")
    print(f"Min anomaly score:     {min(anomaly_scores):.1f}")

    # Label anomaly distribution
    normal_scores = [s for s, l in zip(anomaly_scores, y_test) if l == "Normal"]
    threat_scores = [s for s, l in zip(anomaly_scores, y_test) if l != "Normal"]
    if normal_scores:
        print(f"Normal avg score:      {sum(normal_scores)/len(normal_scores):.1f}")
    if threat_scores:
        print(f"Threat avg score:      {sum(threat_scores)/len(threat_scores):.1f}")

    print()
    print("=" * 60)
    print("EVALUATION NOTE: Synthetic data evaluation only.")
    print("Results do NOT represent real-world detection capability.")
    print("=" * 60)


if __name__ == "__main__":
    main()
