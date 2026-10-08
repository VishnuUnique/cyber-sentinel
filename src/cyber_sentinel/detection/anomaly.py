"""Isolation Forest anomaly detector."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


class IsolationForestDetector:
    """Unsupervised anomaly detector using Isolation Forest.

    Scores are normalized to 0-100 where higher = more anomalous.
    Can be replaced by One-Class SVM via the same interface.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the detector with configuration.

        Args:
            config: Dict with keys: contamination, random_state, model_version.
        """
        cfg = config or {}
        self.contamination: float = float(cfg.get("contamination", 0.05))
        self.random_state: int = int(cfg.get("random_state", 42))
        self.model_version: str = str(cfg.get("model_version", "1.0.0"))

        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None

    def train(self, X: np.ndarray) -> None:
        """Fit the Isolation Forest and StandardScaler on feature matrix X.

        Args:
            X: 2D numpy array of shape (n_samples, n_features).
        """
        if X is None or len(X) == 0:
            raise ValueError("Training data X must be non-empty")

        X = np.array(X, dtype=np.float64)

        # Replace NaN/Inf with 0
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        logger.info(
            "IsolationForest trained on %d samples, %d features",
            X.shape[0],
            X.shape[1],
        )

    def predict(self, X: np.ndarray) -> Dict[str, Any]:
        """Run anomaly detection on feature vector(s).

        Args:
            X: 1D or 2D numpy array. If 1D, treated as a single sample.

        Returns:
            Dict with keys:
            - is_anomaly (bool)
            - anomaly_score (float, 0-100, higher = more anomalous)
            - raw_score (float, the raw decision function value)
        """
        if not self.is_trained:
            logger.warning("IsolationForestDetector not trained; returning default score 50")
            return {"is_anomaly": False, "anomaly_score": 50.0, "raw_score": 0.0}

        X = np.array(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = self._scaler.transform(X)

        # decision_function returns negative scores; lower = more anomalous
        raw_scores = self._model.decision_function(X_scaled)
        predictions = self._model.predict(X_scaled)  # -1 anomaly, 1 normal

        # Normalize: (0.5 - raw) / 1.0 * 100, clamped [0, 100]
        # raw_score near -0.5 (anomalous) → ~100, near 0.5 (normal) → ~0
        raw_score = float(raw_scores[0])
        anomaly_score = float(np.clip((0.5 - raw_score) / 1.0 * 100, 0.0, 100.0))
        is_anomaly = bool(predictions[0] == -1)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "raw_score": raw_score,
        }

    def save(self, path: str) -> None:
        """Save the trained model and scaler to disk.

        Args:
            path: File path (joblib format).
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model": self._model,
            "scaler": self._scaler,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "model_version": self.model_version,
        }
        joblib.dump(payload, p)
        logger.info("IsolationForestDetector saved to %s", p)

    def load(self, path: str) -> None:
        """Load the model and scaler from disk.

        Args:
            path: File path (joblib format).
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model file not found: {p}")
        payload = joblib.load(p)
        self._model = payload["model"]
        self._scaler = payload["scaler"]
        self.contamination = payload.get("contamination", self.contamination)
        self.random_state = payload.get("random_state", self.random_state)
        self.model_version = payload.get("model_version", self.model_version)
        logger.info("IsolationForestDetector loaded from %s", p)

    @property
    def is_trained(self) -> bool:
        """True if the model has been trained or loaded."""
        return self._model is not None and self._scaler is not None
