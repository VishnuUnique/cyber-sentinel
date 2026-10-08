"""Evidence engine: generates human-readable evidence from features."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_SCORES = {"critical": 100.0, "high": 70.0, "medium": 40.0, "low": 20.0}


@dataclass
class EvidenceItem:
    """A single piece of feature-level evidence for a detection."""

    feature_name: str
    observed_value: float
    threshold_value: Optional[float]
    description: str
    severity: str  # low | medium | high | critical


class EvidenceEngine:
    """Generates evidence items from feature values and detection results.

    Rules are deterministic and threshold-driven.
    """

    def __init__(self, thresholds: Dict[str, Any]):
        """Initialize with threshold configuration.

        Args:
            thresholds: Dict of threshold names to numeric values.
        """
        self.thresholds = thresholds

    def generate(
        self,
        features: Dict[str, float],
        classification: str,
        anomaly_score: float,
    ) -> List[EvidenceItem]:
        """Generate evidence items from feature values.

        Args:
            features: Dict mapping feature name to float value.
            classification: Predicted classification label.
            anomaly_score: Normalized anomaly score (0-100).

        Returns:
            List of EvidenceItem sorted by severity (critical first).
        """
        items: List[EvidenceItem] = []
        t = self.thresholds

        # --- Port diversity / port scan ---
        unique_ports = features.get("unique_dest_ports", 0.0)
        if unique_ports > t.get("unique_ports_critical", 40):
            items.append(EvidenceItem(
                feature_name="unique_dest_ports",
                observed_value=unique_ports,
                threshold_value=t.get("unique_ports_critical", 40),
                description=f"Unique destination ports = {int(unique_ports)} (critical port diversity)",
                severity="critical",
            ))
        elif unique_ports > t.get("unique_ports_high", 20):
            items.append(EvidenceItem(
                feature_name="unique_dest_ports",
                observed_value=unique_ports,
                threshold_value=t.get("unique_ports_high", 20),
                description=f"Unique destination ports = {int(unique_ports)} (high port diversity)",
                severity="high",
            ))

        # --- Authentication failures ---
        failed_auth = features.get("failed_auth_count", 0.0)
        if failed_auth > t.get("failed_auth_critical", 30):
            items.append(EvidenceItem(
                feature_name="failed_auth_count",
                observed_value=failed_auth,
                threshold_value=t.get("failed_auth_critical", 30),
                description=f"Failed authentication attempts = {int(failed_auth)} (critical)",
                severity="critical",
            ))
        elif failed_auth > t.get("failed_auth_high", 10):
            items.append(EvidenceItem(
                feature_name="failed_auth_count",
                observed_value=failed_auth,
                threshold_value=t.get("failed_auth_high", 10),
                description=f"Failed authentication attempts = {int(failed_auth)}",
                severity="high",
            ))

        # --- Large data transfer (exfiltration indicator) ---
        total_bytes = features.get("total_bytes", 0.0)
        if total_bytes > t.get("bytes_out_critical", 100_000_000):
            items.append(EvidenceItem(
                feature_name="total_bytes",
                observed_value=total_bytes,
                threshold_value=t.get("bytes_out_critical", 100_000_000),
                description=f"Outbound bytes = {total_bytes / (1024*1024):.1f} MB (critical volume)",
                severity="critical",
            ))
        elif total_bytes > t.get("bytes_out_high", 10_000_000):
            items.append(EvidenceItem(
                feature_name="total_bytes",
                observed_value=total_bytes,
                threshold_value=t.get("bytes_out_high", 10_000_000),
                description=f"Outbound bytes = {total_bytes / (1024*1024):.1f} MB",
                severity="high",
            ))

        # --- Unique internal peers (lateral movement) ---
        unique_peers = features.get("unique_dest_ips", 0.0)
        if unique_peers > t.get("unique_peers_critical", 15):
            items.append(EvidenceItem(
                feature_name="unique_dest_ips",
                observed_value=unique_peers,
                threshold_value=t.get("unique_peers_critical", 15),
                description=f"Unique internal peers = {int(unique_peers)} (critical spread)",
                severity="critical",
            ))
        elif unique_peers > t.get("unique_peers_high", 8):
            items.append(EvidenceItem(
                feature_name="unique_dest_ips",
                observed_value=unique_peers,
                threshold_value=t.get("unique_peers_high", 8),
                description=f"Unique internal peers = {int(unique_peers)}",
                severity="medium",
            ))

        # --- High connection rate ---
        conn_rate = features.get("connection_rate", 0.0)
        if conn_rate > t.get("connection_rate_critical", 60):
            items.append(EvidenceItem(
                feature_name="connection_rate",
                observed_value=conn_rate,
                threshold_value=t.get("connection_rate_critical", 60),
                description=f"Connection rate = {conn_rate:.1f}/min (critical)",
                severity="critical",
            ))
        elif conn_rate > t.get("connection_rate_high", 30):
            items.append(EvidenceItem(
                feature_name="connection_rate",
                observed_value=conn_rate,
                threshold_value=t.get("connection_rate_high", 30),
                description=f"Connection rate = {conn_rate:.1f}/min",
                severity="high",
            ))

        # --- Auth failure rate ---
        auth_failure_rate = features.get("auth_failure_rate", 0.0)
        if auth_failure_rate > 0.7:
            items.append(EvidenceItem(
                feature_name="auth_failure_rate",
                observed_value=auth_failure_rate,
                threshold_value=0.7,
                description=f"Authentication failure rate = {auth_failure_rate:.0%}",
                severity="high",
            ))

        # --- New destination ratio ---
        new_dest_ratio = features.get("new_dest_ip_ratio", 0.0)
        if new_dest_ratio > 0.5:
            items.append(EvidenceItem(
                feature_name="new_dest_ip_ratio",
                observed_value=new_dest_ratio,
                threshold_value=0.5,
                description=f"New destination relationship ratio = {new_dest_ratio:.0%}",
                severity="medium",
            ))

        # --- Port scan indicator ---
        port_scan_ind = features.get("port_scan_indicator", 0.0)
        if port_scan_ind > 0.5:
            items.append(EvidenceItem(
                feature_name="port_scan_indicator",
                observed_value=port_scan_ind,
                threshold_value=0.5,
                description=f"Port scan indicator elevated = {port_scan_ind:.2f}",
                severity="high",
            ))

        # --- Exfil indicator ---
        exfil_ind = features.get("exfil_indicator", 0.0)
        bytes_high = t.get("bytes_out_high", 10_000_000)
        if exfil_ind > bytes_high:
            items.append(EvidenceItem(
                feature_name="exfil_indicator",
                observed_value=exfil_ind,
                threshold_value=float(bytes_high),
                description=f"Data exfiltration indicator = {exfil_ind:.2f}",
                severity="high",
            ))

        # --- High anomaly score ---
        if anomaly_score >= 80:
            items.append(EvidenceItem(
                feature_name="anomaly_score",
                observed_value=anomaly_score,
                threshold_value=80.0,
                description=f"Behavioral anomaly score = {anomaly_score:.1f}/100 (significant deviation)",
                severity="high",
            ))
        elif anomaly_score >= 60:
            items.append(EvidenceItem(
                feature_name="anomaly_score",
                observed_value=anomaly_score,
                threshold_value=60.0,
                description=f"Behavioral anomaly score = {anomaly_score:.1f}/100",
                severity="medium",
            ))

        # Sort: critical first, then high, medium, low
        items.sort(key=lambda e: _SEVERITY_ORDER.get(e.severity, 99))
        return items

    def compute_evidence_score(self, items: List[EvidenceItem]) -> float:
        """Compute a 0-100 evidence score from a list of EvidenceItem objects.

        Args:
            items: List of EvidenceItem instances.

        Returns:
            Float score 0-100. Higher = more severe evidence.
        """
        if not items:
            return 0.0

        # Weighted average of severity scores
        total = sum(_SEVERITY_SCORES.get(item.severity, 0.0) for item in items)
        avg = total / len(items)

        # Scale up slightly if many items
        scale = min(1.5, 1.0 + (len(items) - 1) * 0.1)
        return min(100.0, avg * scale)
