"""Random Forest multi-class threat classifier."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


class RandomForestThreatClassifier:
    """Supervised multi-class threat classifier using Random Forest.

    Classes: Normal, Port Scan, Brute Force, Lateral Movement, Data Exfiltration.
    Architecture allows XGBoost substitution via the same interface.
    """

    CLASSES = [
        "Normal",
        "Port Scan",
        "Brute Force",
        "Lateral Movement",
        "Data Exfiltration",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the classifier with configuration.

        Args:
            config: Dict with keys: n_estimators, random_state, model_version.
        """
        cfg = config or {}
        self.n_estimators: int = int(cfg.get("n_estimators", 100))
        self.random_state: int = int(cfg.get("random_state", 42))
        self.model_version: str = str(cfg.get("model_version", "1.0.0"))

        self._model: Optional[RandomForestClassifier] = None
        self._label_encoder: Optional[LabelEncoder] = None
        self._feature_names: Optional[List[str]] = None

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> None:
        """Train the Random Forest classifier.

        Args:
            X: Feature matrix (n_samples, n_features).
            y: Label array of class name strings.
            feature_names: Ordered list of feature names (must match X columns).
        """
        X = np.array(X, dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        self._feature_names = list(feature_names)
        self._label_encoder = LabelEncoder()
        self._label_encoder.fit(self.CLASSES)  # fit on all classes for stability
        y_encoded = self._label_encoder.transform(y)

        self._model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
            class_weight="balanced",
        )
        self._model.fit(X, y_encoded)

        classes_seen = list(np.unique(y))
        logger.info(
            "RandomForestClassifier trained on %d samples, %d features, classes: %s",
            X.shape[0],
            X.shape[1],
            classes_seen,
        )

    def predict(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Classify a feature vector.

        Args:
            X: 1D or 2D feature array.
            feature_names: Optional list of feature names for input ordering.
                           If provided and differs from training order, columns
                           are reordered to match training feature ordering.

        Returns:
            Dict with:
            - predicted_class (str)
            - class_probabilities (dict: class_name → probability)
            - confidence (float, probability of the predicted class)
        """
        if not self.is_trained:
            logger.warning("Classifier not trained; returning Unknown")
            probs = {c: 1.0 / len(self.CLASSES) for c in self.CLASSES}
            return {
                "predicted_class": "Unknown",
                "class_probabilities": probs,
                "confidence": 1.0 / len(self.CLASSES),
            }

        X = np.array(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Enforce feature ordering
        if feature_names is not None and self._feature_names is not None:
            if feature_names != self._feature_names:
                X = _reorder_features(X, feature_names, self._feature_names)

        proba = self._model.predict_proba(X)[0]

        # Build probabilities dict using the label encoder classes
        class_probs: Dict[str, float] = {}
        for i, cls_encoded in enumerate(self._model.classes_):
            cls_name = self._label_encoder.inverse_transform([cls_encoded])[0]
            class_probs[cls_name] = float(proba[i])

        # Fill in any missing classes with 0
        for cls in self.CLASSES:
            if cls not in class_probs:
                class_probs[cls] = 0.0

        # Predicted class
        best_idx = int(np.argmax(proba))
        best_encoded = self._model.classes_[best_idx]
        predicted_class = self._label_encoder.inverse_transform([best_encoded])[0]
        confidence = float(proba[best_idx])

        return {
            "predicted_class": predicted_class,
            "class_probabilities": class_probs,
            "confidence": confidence,
        }

    def save(self, path: str) -> None:
        """Save the trained model to disk.

        Args:
            path: File path (joblib format). Scaler, label encoder,
                  and feature names are saved alongside.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained classifier")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model": self._model,
            "label_encoder": self._label_encoder,
            "feature_names": self._feature_names,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "model_version": self.model_version,
        }
        joblib.dump(payload, p)
        logger.info("RandomForestClassifier saved to %s", p)

    def load(self, path: str) -> None:
        """Load the model from disk.

        Args:
            path: File path (joblib format).
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model file not found: {p}")
        payload = joblib.load(p)
        self._model = payload["model"]
        self._label_encoder = payload["label_encoder"]
        self._feature_names = payload["feature_names"]
        self.n_estimators = payload.get("n_estimators", self.n_estimators)
        self.random_state = payload.get("random_state", self.random_state)
        self.model_version = payload.get("model_version", self.model_version)
        logger.info("RandomForestClassifier loaded from %s", p)

    @property
    def is_trained(self) -> bool:
        """True if the model has been trained or loaded."""
        return self._model is not None and self._label_encoder is not None

    def get_feature_importance(self) -> Dict[str, float]:
        """Return a dict of feature name → importance score.

        Returns:
            Dict mapping feature names to their importance values.
            Empty dict if not trained.
        """
        if not self.is_trained or self._feature_names is None:
            return {}
        importances = self._model.feature_importances_
        return {
            name: float(imp)
            for name, imp in zip(self._feature_names, importances)
        }


def _reorder_features(
    X: np.ndarray,
    input_names: List[str],
    target_names: List[str],
) -> np.ndarray:
    """Reorder columns in X from input_names order to target_names order.

    Args:
        X: Feature matrix with columns in input_names order.
        input_names: Column names as provided.
        target_names: Column names as expected (training order).

    Returns:
        Reordered feature matrix.
    """
    input_index = {name: i for i, name in enumerate(input_names)}
    reordered = np.zeros((X.shape[0], len(target_names)), dtype=np.float64)
    for j, name in enumerate(target_names):
        if name in input_index:
            reordered[:, j] = X[:, input_index[name]]
    return reordered
