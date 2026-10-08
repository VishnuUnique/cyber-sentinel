#!/usr/bin/env python3
"""
Standalone ingestion CLI wrapper for Cyber Sentinel.

Usage:
    python scripts/ingest.py --input data/samples/mixed.jsonl
    python scripts/ingest.py --input data/samples/mixed.jsonl --db-url sqlite:///database/cyber_sentinel.db
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT / "src"))

import argparse

from cyber_sentinel.database.database import initialize_database, get_session
from cyber_sentinel.database.repository import AlertRepository
from cyber_sentinel.detection.pipeline import SentinelPipeline
from cyber_sentinel.ingestion.parser import TelemetryParser
from cyber_sentinel.utils.logging import setup_logging, get_logger

logger = get_logger(__name__)


def main():
    setup_logging()
    parser = argparse.ArgumentParser(
        description="Ingest telemetry records into Cyber Sentinel database."
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input file (JSON, JSONL, CSV) or '-' for stdin",
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="SQLite database URL (default: from config)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and detect but do not persist to database",
    )
    args = parser.parse_args()

    # Initialize DB
    if not args.dry_run:
        initialize_database(db_url=args.db_url)
        repo = AlertRepository(session_factory=get_session)
    else:
        repo = None

    pipeline = SentinelPipeline(db_repo=repo)

    # Parse input
    tel_parser = TelemetryParser()
    if args.input == "-":
        records, errors = tel_parser.parse_stdin()
    else:
        records, errors = tel_parser.parse_file(args.input)

    if errors:
        for e in errors[:10]:
            logger.warning("Parse error: %s", e)

    print(f"Parsed {len(records)} records from {args.input}")

    # Process
    alerts = pipeline.process_batch(records)
    stats = pipeline.get_stats()

    print(f"\nResults:")
    print(f"  Records processed : {stats['records_processed']}")
    print(f"  Records rejected  : {stats['records_rejected']}")
    print(f"  Noise filtered    : {stats['noise_filtered']}")
    print(f"  Alerts generated  : {len(alerts)}")

    if alerts:
        print(f"\nTop alerts (by risk):")
        top = sorted(alerts, key=lambda a: a.risk_score, reverse=True)[:10]
        for a in top:
            print(
                f"  [{a.risk_band:>10}] {a.source_ip:<18} → {(a.dest_ip or '-'):<18} "
                f"Risk={a.risk_score:5.1f}  Class={a.classification}"
            )

    if not args.dry_run:
        print(f"\nAlerts persisted to database.")
    else:
        print(f"\n[DRY RUN] No data persisted.")


if __name__ == "__main__":
    main()
