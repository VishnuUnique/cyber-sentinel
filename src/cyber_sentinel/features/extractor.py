"""Behavioral feature extractor for network telemetry records."""

from typing import Dict, List, Optional

from cyber_sentinel.ingestion.normalizer import NormalizedRecord
from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)

# Fixed-order list of all feature names
FEATURE_NAMES: List[str] = [
    # Traffic
    "total_events",
    "total_bytes",
    "total_packets",
    "avg_packet_size",
    "connection_rate",
    "bytes_per_second",
    # Destination diversity
    "unique_dest_ips",
    "unique_dest_ports",
    "unique_services",
    "dest_ip_diversity",
    "dest_port_diversity",
    # Authentication
    "failed_auth_count",
    "success_auth_count",
    "auth_failure_rate",
    "auth_burst_rate",
    # Network composition
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "other_proto_ratio",
    "avg_bytes_per_flow",
    # Behavioral indicators
    "new_dest_ip_ratio",
    "port_scan_indicator",
    "exfil_indicator",
    "lateral_movement_indicator",
]


# Common service ports
_SERVICE_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138,
    139, 143, 161, 162, 194, 389, 443, 445, 465, 514, 515, 587, 636, 993,
    995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017,
})


class FeatureExtractor:
    """Extracts behavioral features from a list of NormalizedRecord objects.

    All features are floats and always present (0.0 for missing/empty).
    """

    def extract(
        self,
        records: List[NormalizedRecord],
        window_seconds: int = 60,
    ) -> Dict[str, float]:
        """Extract features from a list of records within a time window.

        Args:
            records: List of NormalizedRecord objects.
            window_seconds: Duration of the time window in seconds.

        Returns:
            Dict mapping feature name to float value (0.0 if not computable).
        """
        # Initialize all features to 0.0
        features: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}

        if not records:
            return features

        n = len(records)
        features["total_events"] = float(n)

        # --- Traffic aggregates ---
        bytes_list = [r.bytes for r in records if r.bytes is not None]
        packets_list = [r.packets for r in records if r.packets is not None]

        total_bytes = sum(bytes_list) if bytes_list else 0.0
        total_packets = sum(packets_list) if packets_list else 0.0
        features["total_bytes"] = float(total_bytes)
        features["total_packets"] = float(total_packets)

        if total_packets > 0 and total_bytes > 0:
            features["avg_packet_size"] = total_bytes / total_packets
        elif bytes_list and packets_list:
            features["avg_packet_size"] = total_bytes / max(total_packets, 1)

        # Connection rate = events per minute
        duration_min = max(window_seconds / 60.0, 1.0 / 60.0)
        features["connection_rate"] = n / duration_min

        # Bytes per second
        duration_sec = max(window_seconds, 1)
        features["bytes_per_second"] = total_bytes / duration_sec

        # --- Destination diversity ---
        dest_ips = [r.dest_ip for r in records if r.dest_ip is not None]
        dest_ports = [r.dest_port for r in records if r.dest_port is not None]
        src_ips = [r.source_ip for r in records if r.source_ip is not None]

        unique_dest_ips = len(set(dest_ips))
        unique_dest_ports = len(set(dest_ports))
        features["unique_dest_ips"] = float(unique_dest_ips)
        features["unique_dest_ports"] = float(unique_dest_ports)

        # Unique services = dest ports that are well-known service ports
        unique_services = len(set(dest_ports) & _SERVICE_PORTS)
        features["unique_services"] = float(unique_services)

        # Diversity ratios (0-1): how spread out are the destinations?
        features["dest_ip_diversity"] = float(unique_dest_ips) / max(n, 1)
        features["dest_port_diversity"] = float(unique_dest_ports) / max(n, 1)

        # --- Authentication ---
        auth_events = [r for r in records if r.auth_status is not None]
        failed = sum(1 for r in auth_events if r.auth_status == "failure")
        succeeded = sum(1 for r in auth_events if r.auth_status == "success")
        features["failed_auth_count"] = float(failed)
        features["success_auth_count"] = float(succeeded)

        total_auth = failed + succeeded
        if total_auth > 0:
            features["auth_failure_rate"] = failed / total_auth
        else:
            features["auth_failure_rate"] = 0.0

        # Auth burst rate: auth events per minute
        features["auth_burst_rate"] = total_auth / duration_min

        # --- Protocol ratios ---
        protocols = [r.protocol for r in records if r.protocol is not None]
        if protocols:
            tcp = sum(1 for p in protocols if p == "TCP")
            udp = sum(1 for p in protocols if p == "UDP")
            icmp = sum(1 for p in protocols if p in ("ICMP", "ICMPV6"))
            other = len(protocols) - tcp - udp - icmp
            total_proto = len(protocols)
            features["tcp_ratio"] = tcp / total_proto
            features["udp_ratio"] = udp / total_proto
            features["icmp_ratio"] = icmp / total_proto
            features["other_proto_ratio"] = other / total_proto

        # Avg bytes per flow
        if n > 0:
            features["avg_bytes_per_flow"] = total_bytes / n

        # --- Behavioral indicators ---
        # New dest IP ratio: what fraction of dest IPs have appeared only once?
        if dest_ips:
            from collections import Counter
            ip_counts = Counter(dest_ips)
            new_ips = sum(1 for c in ip_counts.values() if c == 1)
            features["new_dest_ip_ratio"] = new_ips / unique_dest_ips if unique_dest_ips > 0 else 0.0
        else:
            features["new_dest_ip_ratio"] = 0.0

        # Port scan indicator: high unique ports relative to connection count and per unique src-dest pair
        # Normalized 0-1 where 1 = classic port scan signature
        if dest_ports and src_ips:
            # Port scan = many unique dest ports from same source
            unique_src_ips = len(set(src_ips))
            ports_per_source = unique_dest_ports / max(unique_src_ips, 1)
            # Scale: 50 ports/source = 1.0
            features["port_scan_indicator"] = min(1.0, ports_per_source / 50.0)
        else:
            features["port_scan_indicator"] = 0.0

        # Exfil indicator: high bytes outbound, low event count
        # High bytes + few events = bulk transfer = exfil
        if n > 0:
            features["exfil_indicator"] = total_bytes / max(n, 1)
        else:
            features["exfil_indicator"] = 0.0

        # Lateral movement indicator: internal dest IP diversity + auth events
        # Many unique internal peers + auth events = lateral movement
        if unique_dest_ips > 0:
            lm = (unique_dest_ips / max(n, 1)) * (1 + failed / max(total_auth, 1))
            features["lateral_movement_indicator"] = min(1.0, lm)
        else:
            features["lateral_movement_indicator"] = 0.0

        return features

    def to_vector(self, features: Dict[str, float]) -> list:
        """Convert a feature dict to an ordered list matching FEATURE_NAMES.

        Args:
            features: Dict mapping feature name to value.

        Returns:
            List of floats in FEATURE_NAMES order.
        """
        return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
