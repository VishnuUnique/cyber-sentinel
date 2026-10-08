"""Tests for telemetry ingestion: parsing and validation."""

import json
import pytest

from cyber_sentinel.ingestion.parser import TelemetryParser
from cyber_sentinel.ingestion.validator import RecordValidator


class TestTelemetryParser:
    def setup_method(self):
        self.parser = TelemetryParser()

    def test_valid_record_parses(self, sample_normal_record):
        """A valid JSON record should parse without errors."""
        text = json.dumps(sample_normal_record)
        records, errors = self.parser.parse_json(text)
        assert len(records) == 1
        assert records[0]["source_ip"] == "10.0.0.10"
        assert len(errors) == 0

    def test_missing_timestamp_uses_default(self):
        """A record missing timestamp should still validate with a default."""
        validator = RecordValidator()
        rec = {"source_ip": "10.0.0.1", "event_type": "flow"}
        validated, errors = validator.validate(rec)
        assert validated.get("timestamp") is not None
        assert any("timestamp" in e.lower() for e in errors)

    def test_missing_source_ip_returns_error(self):
        """A record missing source_ip should produce a validation error."""
        validator = RecordValidator()
        rec = {"timestamp": "2026-10-08T10:00:01Z", "event_type": "flow"}
        validated, errors = validator.validate(rec)
        assert any("source_ip" in e for e in errors)

    def test_malformed_json_does_not_crash(self):
        """Malformed JSON should return empty records and error messages."""
        records, errors = self.parser.parse_json("{not valid json}")
        assert records == []
        assert len(errors) > 0

    def test_invalid_ip_rejected(self, sample_invalid_ip_record):
        """A record with invalid IP should have source_ip=None after validation."""
        validator = RecordValidator()
        validated, errors = validator.validate(sample_invalid_ip_record)
        assert validated.get("source_ip") is None
        assert any("source_ip" in e for e in errors)

    def test_port_out_of_range_rejected(self):
        """Ports outside 0-65535 should trigger validation errors."""
        validator = RecordValidator()
        rec = {
            "timestamp": "2026-10-08T10:00:01Z",
            "source_ip": "10.0.0.1",
            "dest_port": 99999,
            "event_type": "flow",
        }
        validated, errors = validator.validate(rec)
        assert validated.get("dest_port") is None
        assert any("dest_port" in e for e in errors)

    def test_unknown_event_type_handled(self):
        """Unknown event types should be normalized to lowercase but not error."""
        validator = RecordValidator()
        rec = {
            "timestamp": "2026-10-08T10:00:01Z",
            "source_ip": "10.0.0.1",
            "event_type": "CUSTOM_EVENT_XYZ",
        }
        validated, errors = validator.validate(rec)
        assert validated["event_type"] == "custom_event_xyz"

    def test_jsonl_multiple_records(self):
        """JSONL with multiple lines should parse all records."""
        lines = [
            '{"source_ip": "10.0.0.1", "event_type": "flow", "timestamp": "2026-10-08T10:00:01Z"}',
            '{"source_ip": "10.0.0.2", "event_type": "dns", "timestamp": "2026-10-08T10:00:02Z"}',
            '{"source_ip": "10.0.0.3", "event_type": "http", "timestamp": "2026-10-08T10:00:03Z"}',
        ]
        records, errors = self.parser.parse_jsonl("\n".join(lines))
        assert len(records) == 3
        assert len(errors) == 0

    def test_csv_format_parsed(self):
        """CSV input should be parsed into records."""
        csv_text = (
            "timestamp,source_ip,dest_ip,dest_port,event_type\n"
            "2026-10-08T10:00:01Z,10.0.0.1,10.0.0.2,443,flow\n"
            "2026-10-08T10:00:02Z,10.0.0.3,10.0.0.4,80,http\n"
        )
        records, errors = self.parser.parse_csv(csv_text)
        assert len(records) == 2
        assert records[0]["source_ip"] == "10.0.0.1"

    def test_empty_input_returns_empty(self):
        """Empty input should return empty records and no errors."""
        records, errors = self.parser.parse("")
        assert records == []
        assert errors == []
