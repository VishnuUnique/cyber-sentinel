"""Security utility functions for Cyber Sentinel."""

import ipaddress
from typing import Optional


# Keys that should be sanitized before logging
_SENSITIVE_KEYS = frozenset({"password", "secret", "token", "api_key", "auth_token", "credential"})

# RFC1918 private networks
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


def sanitize_ip(ip: str) -> str:
    """Validate and normalize an IP address string.

    Args:
        ip: IP address string to sanitize.

    Returns:
        Normalized IP address string.

    Raises:
        ValueError: If the IP address is invalid.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return str(addr)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip!r}") from exc


def is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in an RFC1918 private range.

    Args:
        ip: IP address string to check.

    Returns:
        True if the IP is private/internal, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return any(addr in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def sanitize_record(record: dict) -> dict:
    """Remove or mask sensitive keys from a record before logging.

    Args:
        record: Dictionary that may contain sensitive fields.

    Returns:
        New dictionary with sensitive values replaced by '***'.
    """
    sanitized = {}
    for key, value in record.items():
        if key.lower() in _SENSITIVE_KEYS:
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_record(value)
        else:
            sanitized[key] = value
    return sanitized


def validate_port(port: int) -> bool:
    """Validate that a port number is in valid range (0-65535).

    Args:
        port: Port number to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        return 0 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False
