"""Sliding window buffer for temporal feature extraction."""

import threading
from collections import deque
from datetime import datetime, timezone
from typing import List

from cyber_sentinel.ingestion.normalizer import NormalizedRecord
from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


class SlidingWindowBuffer:
    """Thread-safe sliding window buffer for NormalizedRecord objects.

    Maintains records within configurable time windows to support
    temporal feature extraction.
    """

    def __init__(self, window_sizes: List[int] = None):
        """Initialize the buffer with window sizes in seconds.

        Args:
            window_sizes: List of window durations in seconds.
                         Defaults to [30, 60, 300].
        """
        if window_sizes is None:
            window_sizes = [30, 60, 300]
        self.window_sizes = sorted(window_sizes)
        self._max_window = max(window_sizes) if window_sizes else 300
        self._buffer: deque = deque()
        self._lock = threading.Lock()

    def add(self, record: NormalizedRecord) -> None:
        """Add a record to the buffer.

        Args:
            record: NormalizedRecord to add.
        """
        with self._lock:
            self._buffer.append(record)

    def get_window(self, seconds: int) -> List[NormalizedRecord]:
        """Get all records within the last N seconds.

        Args:
            seconds: Window duration in seconds.

        Returns:
            List of NormalizedRecord objects within the time window.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now.timestamp() - seconds
            result = [
                r for r in self._buffer
                if _ts(r) >= cutoff
            ]
            return result

    def expire(self) -> int:
        """Remove records older than the maximum window size.

        Returns:
            Number of records removed.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now.timestamp() - self._max_window
            before = len(self._buffer)
            while self._buffer and _ts(self._buffer[0]) < cutoff:
                self._buffer.popleft()
            removed = before - len(self._buffer)
            if removed > 0:
                logger.debug("Expired %d records from sliding window buffer", removed)
            return removed

    @property
    def size(self) -> int:
        """Return the current number of records in the buffer."""
        with self._lock:
            return len(self._buffer)

    def clear(self) -> None:
        """Clear all records from the buffer."""
        with self._lock:
            self._buffer.clear()


def _ts(record: NormalizedRecord) -> float:
    """Get timestamp as Unix timestamp float."""
    ts = record.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.timestamp()
