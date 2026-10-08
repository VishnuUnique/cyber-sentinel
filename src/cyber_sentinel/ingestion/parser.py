"""Telemetry parser: parses JSON, JSONL, CSV from various sources."""

import csv
import io
import json
import sys
from pathlib import Path
from typing import List, Tuple

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)


class TelemetryParser:
    """Parse network telemetry from JSON, JSONL, CSV, file, or stdin.

    All methods return partial results on malformed input rather than raising.
    """

    def parse_json(self, text: str) -> Tuple[List[dict], List[str]]:
        """Parse a JSON string — either a single object or a list of objects.

        Returns:
            (records, errors) tuple.
        """
        records: List[dict] = []
        errors: List[str] = []
        text = text.strip()
        if not text:
            return records, errors
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                records.append(data)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    if isinstance(item, dict):
                        records.append(item)
                    else:
                        errors.append(f"Item {i} is not a dict: {type(item).__name__}")
            else:
                errors.append(f"Expected dict or list, got {type(data).__name__}")
        except json.JSONDecodeError as exc:
            errors.append(f"JSON parse error: {exc}")
        return records, errors

    def parse_jsonl(self, text: str) -> Tuple[List[dict], List[str]]:
        """Parse a JSONL (JSON Lines) string — one JSON object per line.

        Returns:
            (records, errors) tuple.
        """
        records: List[dict] = []
        errors: List[str] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    errors.append(f"Line {lineno}: expected dict, got {type(obj).__name__}")
            except json.JSONDecodeError as exc:
                errors.append(f"Line {lineno}: {exc}")
        return records, errors

    def parse_csv(self, text: str) -> Tuple[List[dict], List[str]]:
        """Parse a CSV string with headers into a list of dicts.

        Returns:
            (records, errors) tuple.
        """
        records: List[dict] = []
        errors: List[str] = []
        if not text.strip():
            return records, errors
        try:
            reader = csv.DictReader(io.StringIO(text))
            for i, row in enumerate(reader, start=1):
                try:
                    # Convert numeric-looking strings to numbers
                    cleaned: dict = {}
                    for k, v in row.items():
                        if v is None or v == "":
                            cleaned[k] = None
                        else:
                            cleaned[k] = _try_numeric(v)
                    records.append(cleaned)
                except Exception as exc:
                    errors.append(f"CSV row {i}: {exc}")
        except csv.Error as exc:
            errors.append(f"CSV parse error: {exc}")
        return records, errors

    def parse_file(self, path: str) -> Tuple[List[dict], List[str]]:
        """Parse a file, auto-detecting format from extension.

        Supported extensions: .json, .jsonl, .ndjson, .csv
        Falls back to smart detection if extension is unrecognized.

        Returns:
            (records, errors) tuple.
        """
        p = Path(path)
        errors: List[str] = []
        if not p.exists():
            return [], [f"File not found: {path}"]
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [], [f"Cannot read file {path}: {exc}"]

        ext = p.suffix.lower()
        if ext == ".csv":
            return self.parse_csv(text)
        elif ext in (".jsonl", ".ndjson"):
            return self.parse_jsonl(text)
        elif ext == ".json":
            return self.parse_json(text)
        else:
            return self.parse(text)

    def parse_stdin(self) -> Tuple[List[dict], List[str]]:
        """Read from stdin and parse using smart detection.

        Returns:
            (records, errors) tuple.
        """
        try:
            text = sys.stdin.read()
        except Exception as exc:
            return [], [f"Cannot read stdin: {exc}"]
        return self.parse(text)

    def parse(self, input_str: str) -> Tuple[List[dict], List[str]]:
        """Smart-detect format and parse: tries JSONL, then JSON, then CSV.

        Returns:
            (records, errors) tuple.
        """
        text = (input_str or "").strip()
        if not text:
            return [], []

        # Try JSONL first (newline-delimited JSON)
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if lines:
            first_valid = None
            for line in lines:
                try:
                    obj = json.loads(line)
                    first_valid = obj
                    break
                except json.JSONDecodeError:
                    break

            if first_valid is not None and isinstance(first_valid, dict):
                records, errors = self.parse_jsonl(text)
                if records:
                    return records, errors

        # Try JSON array/object
        if text.startswith("{") or text.startswith("["):
            records, errors = self.parse_json(text)
            if records:
                return records, errors

        # Try CSV
        if "," in text or "\t" in text:
            records, errors = self.parse_csv(text)
            if records:
                return records, errors

        return [], [f"Unable to detect format for input of length {len(text)}"]


def _try_numeric(value: str):
    """Try to convert a string to int or float, otherwise return as-is."""
    try:
        int_val = int(value)
        return int_val
    except ValueError:
        pass
    try:
        float_val = float(value)
        return float_val
    except ValueError:
        pass
    return value
