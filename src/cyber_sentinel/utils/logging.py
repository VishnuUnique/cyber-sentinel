"""Logging utilities for Cyber Sentinel."""

import logging
import os
from pathlib import Path


_configured = False


def setup_logging(level: str = "INFO") -> None:
    """Configure application-wide logging with file and console handlers."""
    global _configured

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Determine log file path
    try:
        from cyber_sentinel.config.settings import settings
        log_dir = settings.project_root / "logs"
    except Exception:
        log_dir = Path("logs")

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "cyber_sentinel.log"

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers if reconfiguring
    if _configured:
        root_logger.handlers.clear()

    formatter = logging.Formatter(log_format, datefmt=date_format)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError:
        pass  # If we can't write log file, console-only is fine

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a named logger. Sets up logging if not already configured."""
    global _configured
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
