"""Settings module for Cyber Sentinel.

Loads configuration from config.yaml with environment variable overrides.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


def _find_project_root() -> Path:
    """Find the project root by walking up from this file."""
    current = Path(__file__).resolve()
    # Walk up looking for config/config.yaml
    for parent in current.parents:
        if (parent / "config" / "config.yaml").exists():
            return parent
        if (parent / "pyproject.toml").exists():
            return parent
    # Fallback: go up 5 levels from src/cyber_sentinel/config/settings.py
    return current.parents[4]


PROJECT_ROOT = _find_project_root()


@dataclass
class AnomalyConfig:
    contamination: float = 0.05
    random_state: int = 42
    model_version: str = "1.0.0"


@dataclass
class ClassifierConfig:
    n_estimators: int = 100
    random_state: int = 42
    model_version: str = "1.0.0"


@dataclass
class RiskConfig:
    anomaly_weight: float = 0.40
    classifier_weight: float = 0.30
    evidence_weight: float = 0.30
    max_risk: float = 70.0


@dataclass
class NoiseConfig:
    enabled: bool = True
    event_types: List[str] = field(default_factory=lambda: ["dhcp", "arp", "multicast", "service_discovery"])


@dataclass
class ModelsConfig:
    anomaly_path: str = "models/anomaly/isolation_forest.joblib"
    classifier_path: str = "models/classifier/random_forest.joblib"
    label_encoder_path: str = "models/classifier/label_encoder.joblib"
    feature_list_path: str = "models/classifier/feature_list.joblib"
    scaler_path: str = "models/anomaly/scaler.joblib"


@dataclass
class ThresholdsConfig:
    unique_ports_high: int = 20
    unique_ports_critical: int = 40
    failed_auth_high: int = 10
    failed_auth_critical: int = 30
    bytes_out_high: int = 10_000_000
    bytes_out_critical: int = 100_000_000
    unique_peers_high: int = 8
    unique_peers_critical: int = 15
    connection_rate_high: int = 30
    connection_rate_critical: int = 60


@dataclass
class DatabaseConfig:
    url: str = "sqlite:///database/cyber_sentinel.db"


class Settings:
    """Application settings loaded from config.yaml with env var overrides."""

    def __init__(self, config_path: Optional[str] = None):
        self.project_root = PROJECT_ROOT

        # Determine config file path
        if config_path:
            cfg_path = Path(config_path)
        else:
            env_path = os.environ.get("CONFIG_PATH")
            if env_path:
                cfg_path = Path(env_path)
                if not cfg_path.is_absolute():
                    cfg_path = self.project_root / cfg_path
            else:
                cfg_path = self.project_root / "config" / "config.yaml"

        self._raw: Dict[str, Any] = {}
        if cfg_path.exists():
            with open(cfg_path, "r", encoding="utf-8") as f:
                self._raw = yaml.safe_load(f) or {}

        self._load()

    def _load(self) -> None:
        """Load settings from raw config dict."""
        # Basic settings
        self.window_seconds: int = self._raw.get("window_seconds", 60)
        self.feature_windows: List[int] = self._raw.get("feature_windows", [30, 60, 300])

        # Sub-configs
        anomaly_raw = self._raw.get("anomaly", {})
        self.anomaly = AnomalyConfig(
            contamination=anomaly_raw.get("contamination", 0.05),
            random_state=anomaly_raw.get("random_state", 42),
            model_version=anomaly_raw.get("model_version", "1.0.0"),
        )

        classifier_raw = self._raw.get("classifier", {})
        self.classifier = ClassifierConfig(
            n_estimators=classifier_raw.get("n_estimators", 100),
            random_state=classifier_raw.get("random_state", 42),
            model_version=classifier_raw.get("model_version", "1.0.0"),
        )

        risk_raw = self._raw.get("risk", {})
        self.risk = RiskConfig(
            anomaly_weight=risk_raw.get("anomaly_weight", 0.40),
            classifier_weight=risk_raw.get("classifier_weight", 0.30),
            evidence_weight=risk_raw.get("evidence_weight", 0.30),
            max_risk=float(risk_raw.get("max_risk", 70.0)),
        )

        noise_raw = self._raw.get("noise", {})
        self.noise = NoiseConfig(
            enabled=noise_raw.get("enabled", True),
            event_types=noise_raw.get("event_types", ["dhcp", "arp", "multicast", "service_discovery"]),
        )

        models_raw = self._raw.get("models", {})
        self.models = ModelsConfig(
            anomaly_path=models_raw.get("anomaly_path", "models/anomaly/isolation_forest.joblib"),
            classifier_path=models_raw.get("classifier_path", "models/classifier/random_forest.joblib"),
            label_encoder_path=models_raw.get("label_encoder_path", "models/classifier/label_encoder.joblib"),
            feature_list_path=models_raw.get("feature_list_path", "models/classifier/feature_list.joblib"),
            scaler_path=models_raw.get("scaler_path", "models/anomaly/scaler.joblib"),
        )

        thresholds_raw = self._raw.get("thresholds", {})
        self.thresholds = ThresholdsConfig(
            unique_ports_high=thresholds_raw.get("unique_ports_high", 20),
            unique_ports_critical=thresholds_raw.get("unique_ports_critical", 40),
            failed_auth_high=thresholds_raw.get("failed_auth_high", 10),
            failed_auth_critical=thresholds_raw.get("failed_auth_critical", 30),
            bytes_out_high=thresholds_raw.get("bytes_out_high", 10_000_000),
            bytes_out_critical=thresholds_raw.get("bytes_out_critical", 100_000_000),
            unique_peers_high=thresholds_raw.get("unique_peers_high", 8),
            unique_peers_critical=thresholds_raw.get("unique_peers_critical", 15),
            connection_rate_high=thresholds_raw.get("connection_rate_high", 30),
            connection_rate_critical=thresholds_raw.get("connection_rate_critical", 60),
        )

        db_raw = self._raw.get("database", {})
        self.database = DatabaseConfig(
            url=os.environ.get("DATABASE_URL", db_raw.get("url", "sqlite:///database/cyber_sentinel.db")),
        )

        # Logging
        self.log_level: str = os.environ.get("LOG_LEVEL", "INFO")

        # Apply env var overrides
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        max_risk_env = os.environ.get("MAX_RISK")
        if max_risk_env:
            self.risk.max_risk = float(max_risk_env)

    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a path relative to the project root."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return self.project_root / p

    def get_anomaly_model_path(self) -> Path:
        return self.resolve_path(self.models.anomaly_path)

    def get_classifier_model_path(self) -> Path:
        return self.resolve_path(self.models.classifier_path)

    def get_label_encoder_path(self) -> Path:
        return self.resolve_path(self.models.label_encoder_path)

    def get_feature_list_path(self) -> Path:
        return self.resolve_path(self.models.feature_list_path)

    def get_scaler_path(self) -> Path:
        return self.resolve_path(self.models.scaler_path)

    def get_database_url(self) -> str:
        """Get the database URL, resolving relative SQLite paths."""
        url = self.database.url
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            rel = url[len("sqlite:///"):]
            abs_path = self.resolve_path(rel)
            # Ensure directory exists
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{abs_path}"
        return url


# Global settings instance
settings = Settings()
