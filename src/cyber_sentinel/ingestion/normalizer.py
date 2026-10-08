"""Record normalizer: converts validated records to NormalizedRecord dataclass."""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class NormalizedRecord:
    """A validated and normalized telemetry record with typed fields."""

    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes: Optional[float] = None
    packets: Optional[float] = None
    auth_status: Optional[str] = None  # "success" | "failure" | None
    event_type: str = "unknown"
    extra: dict = field(default_factory=dict)

    def is_auth_failure(self) -> bool:
        return self.auth_status == "failure"

    def is_auth_success(self) -> bool:
        return self.auth_status == "success"


class RecordNormalizer:
    """Normalizes validated record dicts into NormalizedRecord instances."""

    def normalize(self, validated: dict) -> NormalizedRecord:
        """Convert a validated record dict to NormalizedRecord.

        Args:
            validated: A validated record dict (from RecordValidator).

        Returns:
            NormalizedRecord instance with typed, normalized fields.
        """
        # Timestamp → UTC datetime
        ts_raw = validated.get("timestamp")
        ts = _parse_to_utc(ts_raw)

        # Source IP — normalize to compressed form
        src_ip = validated.get("source_ip") or "0.0.0.0"
        src_ip = _normalize_ip(src_ip)

        # Dest IP
        dest_ip = validated.get("dest_ip")
        if dest_ip:
            dest_ip = _normalize_ip(dest_ip)

        # Ports
        src_port = validated.get("src_port")
        dest_port = validated.get("dest_port")
        if src_port is not None:
            src_port = int(src_port)
        if dest_port is not None:
            dest_port = int(dest_port)

        # Protocol
        protocol = validated.get("protocol")

        # Bytes / packets as float
        bytes_val = validated.get("bytes")
        packets_val = validated.get("packets")
        if bytes_val is not None:
            bytes_val = float(bytes_val)
        if packets_val is not None:
            packets_val = float(packets_val)

        # Auth status
        auth_status = validated.get("auth_status")  # already normalized in validator

        # Event type
        event_type = validated.get("event_type", "unknown") or "unknown"

        # Collect extra fields
        known = {
            "timestamp", "source_ip", "dest_ip", "src_port", "dest_port",
            "protocol", "bytes", "packets", "auth_status", "event_type", "_errors"
        }
        extra = {k: v for k, v in validated.items() if k not in known}

        return NormalizedRecord(
            timestamp=ts,
            source_ip=src_ip,
            dest_ip=dest_ip,
            src_port=src_port,
            dest_port=dest_port,
            protocol=protocol,
            bytes=bytes_val,
            packets=packets_val,
            auth_status=auth_status,
            event_type=event_type,
            extra=extra,
        )


def _parse_to_utc(value) -> datetime:
    """Parse a timestamp value to UTC datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _normalize_ip(ip: str) -> str:
    """Normalize IP address to compressed string form."""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip
