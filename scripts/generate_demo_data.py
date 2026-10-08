#!/usr/bin/env python3
"""
Generate realistic synthetic telemetry data for Cyber Sentinel.

Generates 2000+ records covering:
  - Normal traffic (60%)
  - Port Scan (10%)
  - Brute Force (10%)
  - Lateral Movement (10%)
  - Data Exfiltration (10%)

WARNING: This is SYNTHETIC demo data. It does not represent real-world traffic.
"""

import csv
import json
import random
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ensure src is importable
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT / "src"))

# ── Constants ─────────────────────────────────────────────────────────────────

INTERNAL_SUBNETS = [
    "10.0.0", "10.0.1", "10.0.2", "192.168.1", "192.168.2", "172.16.0",
]
EXTERNAL_IPS = [
    "203.0.113.10", "198.51.100.5", "203.0.113.50", "198.51.100.99",
    "203.0.113.101", "198.51.100.200", "203.0.113.7", "198.51.100.30",
]
COMMON_PORTS = [80, 443, 22, 25, 53, 8080, 8443, 3306, 5432, 6379, 27017]
SCAN_PORTS = list(range(1, 1025))
SSH_RDP_PORTS = [22, 3389]
LATERAL_PORTS = [445, 135, 139, 3389, 5985, 5986]

TOTAL_RECORDS = 2000
SEED = 42
random.seed(SEED)


def _rand_internal_ip() -> str:
    subnet = random.choice(INTERNAL_SUBNETS)
    return f"{subnet}.{random.randint(1, 254)}"


def _rand_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)


def _rand_ts(base: datetime, jitter_seconds: int = 300) -> str:
    offset = random.uniform(0, jitter_seconds)
    return (base + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _flow(src, dst, src_port, dst_port, proto, byt, pkts, event_type, ts, auth=None) -> dict:
    r = {
        "timestamp": ts,
        "source_ip": src,
        "dest_ip": dst,
        "src_port": src_port,
        "dest_port": dst_port,
        "protocol": proto,
        "bytes": byt,
        "packets": pkts,
        "auth_status": auth,
        "event_type": event_type,
    }
    return r


# ── Generators ─────────────────────────────────────────────────────────────────

def gen_normal(n: int, base: datetime):
    records = []
    for _ in range(n):
        src = _rand_internal_ip()
        dst = random.choice([_rand_internal_ip(), _rand_external_ip()])
        dst_port = random.choice(COMMON_PORTS)
        proto = random.choice(["TCP", "UDP"])
        byt = random.randint(200, 50000)
        pkts = max(1, byt // random.randint(500, 1500))
        etype = random.choice(["flow", "dns", "http", "https"])
        ts = _rand_ts(base, 300)
        records.append(_flow(src, dst, random.randint(1024, 65535), dst_port, proto, byt, pkts, etype, ts))
    return records, ["Normal"] * n


def gen_port_scan(n: int, base: datetime):
    records = []
    attacker = _rand_internal_ip()
    targets = [_rand_internal_ip() for _ in range(random.randint(3, 10))]
    ports = random.sample(SCAN_PORTS, min(n, len(SCAN_PORTS)))
    for i in range(n):
        dst = random.choice(targets)
        dst_port = ports[i % len(ports)]
        ts = _rand_ts(base, 60)
        records.append(_flow(
            attacker, dst,
            random.randint(1024, 65535), dst_port,
            "TCP", random.randint(40, 120), 1, "flow", ts,
        ))
    return records, ["Port Scan"] * n


def gen_brute_force(n: int, base: datetime):
    records = []
    attacker = _rand_internal_ip()
    target = _rand_internal_ip()
    dst_port = random.choice(SSH_RDP_PORTS)
    for i in range(n):
        ts = _rand_ts(base, 120)
        # 85% failures, 15% success
        auth = "failure" if random.random() < 0.85 else "success"
        records.append(_flow(
            attacker, target,
            random.randint(1024, 65535), dst_port,
            "TCP", random.randint(300, 800), random.randint(3, 8),
            "authentication", ts, auth,
        ))
    return records, ["Brute Force"] * n


def gen_lateral_movement(n: int, base: datetime):
    records = []
    attacker = _rand_internal_ip()
    targets = [_rand_internal_ip() for _ in range(random.randint(4, 12))]
    for i in range(n):
        dst = targets[i % len(targets)]
        dst_port = random.choice(LATERAL_PORTS)
        auth = random.choice(["success", "failure", None])
        etype = "authentication" if auth else "flow"
        ts = _rand_ts(base, 180)
        records.append(_flow(
            attacker, dst,
            random.randint(1024, 65535), dst_port,
            "TCP", random.randint(500, 5000), random.randint(5, 30),
            etype, ts, auth,
        ))
    return records, ["Lateral Movement"] * n


def gen_data_exfil(n: int, base: datetime):
    records = []
    src = _rand_internal_ip()
    dst = _rand_external_ip()
    for i in range(n):
        # Very high bytes, low event count per record
        byt = random.randint(5_000_000, 100_000_000)
        pkts = byt // random.randint(1024, 9000)
        ts = _rand_ts(base, 600)
        records.append(_flow(
            src, dst,
            random.randint(1024, 65535), random.choice([443, 80, 8080]),
            "TCP", byt, pkts, "flow", ts,
        ))
    return records, ["Data Exfiltration"] * n


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    base = datetime(2026, 10, 8, 10, 0, 0, tzinfo=timezone.utc)
    samples_dir = _ROOT / "data" / "samples"
    training_dir = _ROOT / "data" / "training"
    samples_dir.mkdir(parents=True, exist_ok=True)
    training_dir.mkdir(parents=True, exist_ok=True)

    counts = {
        "Normal": int(TOTAL_RECORDS * 0.60),
        "Port Scan": int(TOTAL_RECORDS * 0.10),
        "Brute Force": int(TOTAL_RECORDS * 0.10),
        "Lateral Movement": int(TOTAL_RECORDS * 0.10),
        "Data Exfiltration": int(TOTAL_RECORDS * 0.10),
    }

    all_records = []
    all_labels = []
    per_class = {}

    generators = {
        "Normal": gen_normal,
        "Port Scan": gen_port_scan,
        "Brute Force": gen_brute_force,
        "Lateral Movement": gen_lateral_movement,
        "Data Exfiltration": gen_data_exfil,
    }

    file_map = {
        "Normal": "normal.jsonl",
        "Port Scan": "port_scan.jsonl",
        "Brute Force": "brute_force.jsonl",
        "Lateral Movement": "lateral_movement.jsonl",
        "Data Exfiltration": "data_exfiltration.jsonl",
    }

    for label, gen_fn in generators.items():
        n = counts[label]
        records, labels = gen_fn(n, base)
        per_class[label] = len(records)

        # Write per-class file
        out_path = samples_dir / file_map[label]
        with open(out_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        all_records.extend(records)
        all_labels.extend(labels)

    # Shuffle for mixed file
    combined = list(zip(all_records, all_labels))
    random.shuffle(combined)
    all_records_shuffled, all_labels_shuffled = zip(*combined)

    # Write mixed sample file
    mixed_path = samples_dir / "mixed.jsonl"
    with open(mixed_path, "w", encoding="utf-8") as f:
        for r in all_records_shuffled:
            f.write(json.dumps(r) + "\n")

    # Write training data (JSONL)
    train_data_path = training_dir / "training_data.jsonl"
    with open(train_data_path, "w", encoding="utf-8") as f:
        for r in all_records_shuffled:
            f.write(json.dumps(r) + "\n")

    # Write labels (CSV)
    labels_path = training_dir / "training_labels.csv"
    with open(labels_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["index", "label"])
        for i, label in enumerate(all_labels_shuffled):
            writer.writerow([i, label])

    # Summary
    print("\n" + "=" * 60)
    print("SYNTHETIC DEMO DATA GENERATION COMPLETE")
    print("=" * 60)
    print("WARNING: This is SYNTHETIC data. Not real-world traffic.")
    print()
    print(f"{'Class':<25} {'Count':>8}")
    print("-" * 35)
    for label, cnt in per_class.items():
        print(f"  {label:<23} {cnt:>8}")
    print("-" * 35)
    print(f"  {'TOTAL':<23} {sum(per_class.values()):>8}")
    print()
    print(f"Samples:  {samples_dir}")
    print(f"Training: {training_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
