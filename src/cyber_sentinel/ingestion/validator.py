"""Record validator: validates raw telemetry record dicts."""

import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)

_AUTH_STATUSES = frozenset({"success", "failure"})
_VALID_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "ICMPV6", "GRE", "ESP", "AH", "SCTP", "OTHER"})


class RecordValidator:
    """Validate raw telemetry record dicts.

    Returns (validated_record, errors). Never raises on malformed input.
    """

    def validate(self, record: dict) -> Tuple[dict, List[str]]:
        """Validate a single raw record dict.

        Args:
            record: Raw record dictionary.

        Returns:
            (validated_record, errors) tuple. validated_record contains
            cleaned values; unknown fields are passed through.
        """
        validated: dict = {}
        errors: List[str] = []

        # --- timestamp ---
        ts_raw = record.get("timestamp")
        if ts_raw is None:
            logger.warning("Record missing timestamp, defaulting to now")
            validated["timestamp"] = datetime.now(timezone.utc).isoformat()
            errors.append("Missing timestamp; defaulted to now")
        else:
            ts_parsed = _parse_timestamp(str(ts_raw))
            if ts_parsed is None:
                logger.warning("Invalid timestamp %r, defaulting to now", ts_raw)
                validated["timestamp"] = datetime.now(timezone.utc).isoformat()
                errors.append(f"Invalid timestamp {ts_raw!r}; defaulted to now")
            else:
                validated["timestamp"] = ts_parsed.isoformat()

        # --- source_ip (required) ---
        src_ip = record.get("source_ip")
        if src_ip is None:
            errors.append("Missing required field: source_ip")
            validated["source_ip"] = None
        else:
            validated_ip = _validate_ip(str(src_ip))
            if validated_ip is None:
                errors.append(f"Invalid source_ip: {src_ip!r}")
                validated["source_ip"] = None
            else:
                validated["source_ip"] = validated_ip

        # --- dest_ip (optional) ---
        dest_ip = record.get("dest_ip")
        if dest_ip is not None:
            validated_ip = _validate_ip(str(dest_ip))
            if validated_ip is None:
                errors.append(f"Invalid dest_ip: {dest_ip!r}")
                validated["dest_ip"] = None
            else:
                validated["dest_ip"] = validated_ip
        else:
            validated["dest_ip"] = None

        # --- src_port (optional) ---
        src_port = record.get("src_port")
        if src_port is not None:
            validated_port = _validate_port(src_port)
            if validated_port is None:
                errors.append(f"Invalid src_port: {src_port!r}")
                validated["src_port"] = None
            else:
                validated["src_port"] = validated_port
        else:
            validated["src_port"] = None

        # --- dest_port (optional) ---
        dest_port = record.get("dest_port")
        if dest_port is not None:
            validated_port = _validate_port(dest_port)
            if validated_port is None:
                errors.append(f"Invalid dest_port: {dest_port!r}")
                validated["dest_port"] = None
            else:
                validated["dest_port"] = validated_port
        else:
            validated["dest_port"] = None

        # --- protocol (optional) ---
        protocol = record.get("protocol")
        if protocol is not None:
            norm = str(protocol).upper().strip()
            if norm not in _VALID_PROTOCOLS:
                # Accept unknown protocols but normalize
                validated["protocol"] = norm
            else:
                validated["protocol"] = norm
        else:
            validated["protocol"] = None

        # --- bytes (optional, non-negative) ---
        bytes_val = record.get("bytes")
        if bytes_val is not None:
            try:
                b = float(bytes_val)
                if b < 0:
                    errors.append(f"bytes must be non-negative, got {b}")
                    validated["bytes"] = 0.0
                else:
                    validated["bytes"] = b
            except (TypeError, ValueError):
                errors.append(f"Invalid bytes: {bytes_val!r}")
                validated["bytes"] = None
        else:
            validated["bytes"] = None

        # --- packets (optional, non-negative) ---
        packets_val = record.get("packets")
        if packets_val is not None:
            try:
                p = float(packets_val)
                if p < 0:
                    errors.append(f"packets must be non-negative, got {p}")
                    validated["packets"] = 0.0
                else:
                    validated["packets"] = p
            except (TypeError, ValueError):
                errors.append(f"Invalid packets: {packets_val!r}")
                validated["packets"] = None
        else:
            validated["packets"] = None

        # --- auth_status (optional) ---
        auth_status = record.get("auth_status")
        if auth_status is not None:
            norm = str(auth_status).lower().strip()
            if norm in _AUTH_STATUSES:
                validated["auth_status"] = norm
            else:
                errors.append(f"Unknown auth_status {auth_status!r}; setting to None")
                validated["auth_status"] = None
        else:
            validated["auth_status"] = None

        # --- event_type (required) ---
        event_type = record.get("event_type")
        if event_type is None:
            errors.append("Missing required field: event_type; defaulting to 'unknown'")
            validated["event_type"] = "unknown"
        else:
            validated["event_type"] = str(event_type).lower().strip()

        # --- pass through unknown fields ---
        known = {
            "timestamp", "source_ip", "dest_ip", "src_port", "dest_port",
            "protocol", "bytes", "packets", "auth_status", "event_type"
        }
        for k, v in record.items():
            if k not in known:
                validated[k] = v

        return validated, errors

    def validate_batch(self, records: List[dict]) -> Tuple[List[dict], List[dict]]:
        """Validate a list of records.

        Returns:
            (valid_records, rejected_records) where each rejected record
            includes an '_errors' key.
        """
        valid: List[dict] = []
        rejected: List[dict] = []
        for record in records:
            validated, errors = self.validate(record)
            # A record is rejected if source_ip is None (required field missing/invalid)
            if validated.get("source_ip") is None and any("source_ip" in e for e in errors):
                validated["_errors"] = errors
                rejected.append(validated)
            else:
                valid.append(validated)
        return valid, rejected


def _parse_timestamp(value: str) -> Optional[datetime]:
    """Try to parse an ISO8601 timestamp string."""
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Try fromisoformat as a last resort
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _validate_ip(value: str) -> Optional[str]:
    """Validate and normalize an IP address. Returns None if invalid."""
    try:
        addr = ipaddress.ip_address(value.strip())
        return str(addr)
    except ValueError:
        return None


def _validate_port(value) -> Optional[int]:
    """Validate a port number (0-65535). Returns None if invalid."""
    try:
        port = int(float(str(value)))
        if 0 <= port <= 65535:
            return port
        return None
    except (TypeError, ValueError):
        return None
