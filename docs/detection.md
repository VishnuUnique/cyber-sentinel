# Cyber Sentinel — Detection Methodology

## Overview

Cyber Sentinel uses a two-layer detection approach that combines unsupervised anomaly detection with supervised threat classification.

## Layer 1: Isolation Forest (Unsupervised Anomaly Detection)

### Why Isolation Forest?
- Efficient on high-dimensional data
- Does not require labeled data for training
- Detects previously unseen anomalies ("zero-day" behaviors)
- Scales well to streaming telemetry

### How It Works
1. The model is trained on all available telemetry (including both normal and malicious samples in the synthetic dataset)
2. For each new window of activity, a feature vector is computed
3. The Isolation Forest assigns a decision score based on how easily the sample is "isolated"
4. Raw scores are normalized to [0, 100]: `score = clamp((0.5 - raw_score) / 1.0 * 100, 0, 100)`
5. Higher scores indicate more anomalous behavior

### Normalization
- Raw Isolation Forest scores are typically in [-0.5, 0.5]
- A raw score near -0.5 (anomalous) maps to ~100
- A raw score near 0.5 (normal) maps to ~0

### Future Extensibility
The `IsolationForestDetector` class implements a standard interface (`train`, `predict`, `save`, `load`). One-Class SVM or any other anomaly detector can be substituted without changing the pipeline.

## Layer 2: Random Forest (Supervised Threat Classification)

### Why Random Forest?
- Handles multi-class classification natively
- Provides feature importance for explainability
- Robust to outliers and irrelevant features
- Fast inference

### Threat Classes
| Class | Description |
|-------|-------------|
| Normal | Benign network traffic |
| Port Scan | Reconnaissance — scanning many ports/hosts |
| Brute Force | Credential attacks via repeated authentication failures |
| Lateral Movement | Internal host-to-host movement on sensitive ports |
| Data Exfiltration | Large data transfers to external destinations |

### Feature Importance
The model exposes `get_feature_importance()` which returns a ranked dict of feature → importance. Key features for each class:

- **Port Scan**: `unique_dest_ports`, `port_scan_indicator`, `connection_rate`
- **Brute Force**: `failed_auth_count`, `auth_failure_rate`, `auth_burst_rate`
- **Lateral Movement**: `unique_dest_ips`, `lateral_movement_indicator`, `tcp_ratio`
- **Data Exfiltration**: `total_bytes`, `exfil_indicator`, `bytes_per_second`

### Future Extensibility
The `RandomForestThreatClassifier` class can be replaced by XGBoost, LightGBM, or any other classifier with the same interface.

## Behavioral Feature Engineering

### Feature Categories (24 total)

**Traffic Features**
- `total_events`: Count of records in window
- `total_bytes`: Sum of bytes
- `total_packets`: Sum of packets
- `avg_packet_size`: Bytes / packets
- `connection_rate`: Events per minute
- `bytes_per_second`: Total bytes / window seconds

**Destination Diversity**
- `unique_dest_ips`: Distinct destination IPs
- `unique_dest_ports`: Distinct destination ports
- `unique_services`: Ports matching well-known service ports
- `dest_ip_diversity`: unique_dest_ips / total_events
- `dest_port_diversity`: unique_dest_ports / total_events

**Authentication**
- `failed_auth_count`: Records with auth_status='failure'
- `success_auth_count`: Records with auth_status='success'
- `auth_failure_rate`: failed / (failed + success)
- `auth_burst_rate`: Auth events per minute

**Network Composition**
- `tcp_ratio`, `udp_ratio`, `icmp_ratio`, `other_proto_ratio`
- `avg_bytes_per_flow`: total_bytes / total_events

**Behavioral Indicators**
- `new_dest_ip_ratio`: Fraction of destination IPs seen only once
- `port_scan_indicator`: Unique ports per source, normalized [0-1]
- `exfil_indicator`: Average bytes per event (high = bulk transfer)
- `lateral_movement_indicator`: Peer diversity × auth events

## Sliding Window

Features are computed over a configurable time window (default 60 seconds). The window buffer maintains records up to the maximum window size (default 300 seconds) and automatically expires old records.

Multiple window sizes allow detection of both rapid bursts and slow-and-low attacks.

## Risk Scoring

```
risk_score = anomaly_score * w_anomaly
           + classifier_confidence_score * w_classifier
           + evidence_score * w_evidence
```

Where:
- `classifier_confidence_score = confidence * 100` for non-Normal classes
- `classifier_confidence_score = confidence * 10` for Normal class
- All weights sum to 1.0 (default: 0.40, 0.30, 0.30)
- Result is clamped to [0, 100]

## Evidence Generation

The evidence engine applies threshold-based rules to generate human-readable explanations:

| Feature | Threshold | Severity |
|---------|-----------|----------|
| unique_dest_ports | >40 | Critical |
| unique_dest_ports | >20 | High |
| failed_auth_count | >30 | Critical |
| failed_auth_count | >10 | High |
| total_bytes | >100MB | Critical |
| total_bytes | >10MB | High |
| connection_rate | >60/min | Critical |
| auth_failure_rate | >70% | High |
| port_scan_indicator | >0.5 | High |
