"""Streamlit operator dashboard for Cyber Sentinel."""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Ensure src/ is on path when running via streamlit directly
_HERE = Path(__file__).resolve()
_SRC = _HERE.parents[3]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Cyber Sentinel",
    layout="wide",
    page_icon="🛡️",
)


def _get_repo():
    """Lazy-load database repository."""
    try:
        from cyber_sentinel.database.database import initialize_database, get_session
        from cyber_sentinel.database.repository import AlertRepository
        initialize_database()
        return AlertRepository(session_factory=get_session)
    except Exception as exc:
        st.error(f"Database connection error: {exc}")
        return None


def _band_color(band: str) -> str:
    return {"Normal": "🟢", "Suspicious": "🟡", "Malicious": "🔴"}.get(band, "⚪")


def main():
    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown(
        "# 🛡️ Cyber Sentinel — Intelligent Threat & Network Anomaly Detection"
    )
    st.markdown("---")

    # ── Sidebar controls ─────────────────────────────────────────────────────
    with st.sidebar:
        st.header("⚙️ Controls")
        risk_min = st.slider("Minimum Risk Score", 0, 100, 0)
        threat_filter = st.selectbox(
            "Threat Filter",
            ["All", "Normal", "Port Scan", "Brute Force", "Lateral Movement", "Data Exfiltration"],
        )
        status_filter = st.selectbox(
            "Status Filter",
            ["All", "new", "acknowledged", "resolved", "false_positive"],
        )
        days_back = st.slider("Show last N days", 1, 90, 7)
        limit = st.number_input("Max alerts to load", 50, 5000, 500, step=50)
        refresh = st.button("🔄 Refresh")
        st.markdown("---")
        st.markdown("**Cyber Sentinel v1.0.0**")
        st.markdown("⚠️ Demo data only")

    # ── Load data ────────────────────────────────────────────────────────────
    repo = _get_repo()
    if repo is None:
        st.warning("Database not available. Run analysis first.")
        return

    records = repo.list_alerts(
        skip=0,
        limit=int(limit),
        risk_min=float(risk_min) if risk_min > 0 else None,
        threat_category=None if threat_filter == "All" else _map_threat(threat_filter),
        status=None if status_filter == "All" else status_filter,
    )

    if not records:
        st.info("🚫 No data yet — run analysis first.\n\n"
                "```bash\npython scripts/generate_demo_data.py\n"
                "python scripts/train_models.py\n"
                "python scripts/ingest.py --input data/samples/mixed.jsonl\n```")
        return

    # Build dataframe
    rows = []
    for r in records:
        rows.append({
            "Time": r.timestamp,
            "Source IP": r.source_ip,
            "Dest IP": r.dest_ip or "-",
            "Classification": r.classification,
            "Threat": r.threat_category,
            "Risk": r.risk_score,
            "Band": r.risk_band,
            "Anomaly": r.anomaly_score,
            "Confidence": r.classifier_confidence,
            "Status": r.status,
            "Alert ID": r.alert_id,
            "evidence_features": r.evidence_features,
            "feature_values": r.feature_values,
        })
    df = pd.DataFrame(rows)

    # ── KPI row ──────────────────────────────────────────────────────────────
    stats = repo.get_statistics()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("📊 Total Events", len(df))
    c2.metric("🚨 Total Alerts", stats["total_alerts"])
    c3.metric("🔴 Malicious", stats["malicious_count"])
    c4.metric("🟡 Suspicious", stats["suspicious_count"])
    c5.metric("📈 Avg Risk", f"{stats['avg_risk_score']:.1f}")

    st.markdown("---")

    # ── Charts row 1 ─────────────────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Threat Distribution")
        threat_dist = repo.get_threat_distribution()
        if threat_dist:
            fig_pie = px.pie(
                names=list(threat_dist.keys()),
                values=list(threat_dist.values()),
                title="Alerts by Classification",
                color_discrete_sequence=px.colors.qualitative.Set2,
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        st.subheader("Risk Score Distribution")
        risk_dist = repo.get_risk_distribution()
        if risk_dist:
            fig_bar = px.bar(
                x=[r["bucket"] for r in risk_dist],
                y=[r["count"] for r in risk_dist],
                labels={"x": "Risk Score Range", "y": "Count"},
                title="Alert Risk Histogram",
                color=[r["count"] for r in risk_dist],
                color_continuous_scale="Reds",
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    # ── Charts row 2 ─────────────────────────────────────────────────────────
    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Alerts Over Time")
        if not df.empty and "Time" in df.columns:
            df_time = df.copy()
            df_time["Time"] = pd.to_datetime(df_time["Time"], errors="coerce")
            df_time = df_time.dropna(subset=["Time"])
            if not df_time.empty:
                df_time["Hour"] = df_time["Time"].dt.floor("h")
                time_counts = df_time.groupby("Hour").size().reset_index(name="Count")
                fig_line = px.line(
                    time_counts,
                    x="Hour",
                    y="Count",
                    title="Alert Volume Over Time",
                    markers=True,
                )
                st.plotly_chart(fig_line, use_container_width=True)

    with col4:
        st.subheader("Top Source IPs")
        top_sources = repo.get_top_sources(limit=10)
        if top_sources:
            src_df = pd.DataFrame(top_sources)
            fig_src = px.bar(
                src_df,
                x="alert_count",
                y="source_ip",
                orientation="h",
                title="Top 10 Source IPs by Alert Count",
                color="alert_count",
                color_continuous_scale="Oranges",
            )
            fig_src.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_src, use_container_width=True)

    st.markdown("---")

    # ── Alert table ───────────────────────────────────────────────────────────
    st.subheader(f"🗂️ Alert Log ({len(df)} records)")

    # Color-code the Band column
    def _style_band(val):
        colors = {"Normal": "background-color: #d4edda", "Suspicious": "background-color: #fff3cd",
                  "Malicious": "background-color: #f8d7da"}
        return colors.get(val, "")

    display_cols = ["Time", "Source IP", "Dest IP", "Classification", "Risk", "Band", "Status"]
    display_df = df[display_cols].copy()
    display_df["Risk"] = display_df["Risk"].round(1)

    try:
        styled = display_df.style.applymap(_style_band, subset=["Band"])
        st.dataframe(styled, use_container_width=True)
    except Exception:
        st.dataframe(display_df, use_container_width=True)

    # ── Alert detail expanders ────────────────────────────────────────────────
    st.subheader("🔍 Alert Details")
    for _, row in df.head(20).iterrows():
        band_icon = _band_color(row["Band"])
        label = (f"{band_icon} [{row['Band']}] {row['Source IP']} → {row['Dest IP']} | "
                 f"{row['Classification']} | Risk: {row['Risk']:.1f}")
        with st.expander(label):
            c_left, c_right = st.columns(2)

            with c_left:
                st.markdown("**Summary**")
                st.markdown(f"- **Alert ID:** `{row['Alert ID']}`")
                st.markdown(f"- **Time:** {row['Time']}")
                st.markdown(f"- **Classification:** {row['Classification']}")
                st.markdown(f"- **Threat Category:** {row['Threat']}")
                st.markdown(f"- **Risk Band:** {row['Band']}")
                st.markdown(f"- **Status:** {row['Status']}")

                # Risk gauge
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=row["Risk"],
                    title={"text": "Risk Score"},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "darkblue"},
                        "steps": [
                            {"range": [0, 30], "color": "#d4edda"},
                            {"range": [30, 70], "color": "#fff3cd"},
                            {"range": [70, 100], "color": "#f8d7da"},
                        ],
                        "threshold": {
                            "line": {"color": "red", "width": 4},
                            "thickness": 0.75,
                            "value": 70,
                        },
                    },
                ))
                fig_gauge.update_layout(height=200, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig_gauge, use_container_width=True)

            with c_right:
                # Evidence
                evidence = row.get("evidence_features")
                if evidence:
                    if isinstance(evidence, str):
                        try:
                            evidence = json.loads(evidence)
                        except Exception:
                            evidence = []
                    if evidence:
                        st.markdown("**Evidence**")
                        for ev in evidence:
                            sev = ev.get("severity", "low")
                            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
                            st.markdown(f"{icon} {ev.get('description', '')}")

                # Feature table
                feat = row.get("feature_values")
                if feat:
                    if isinstance(feat, str):
                        try:
                            feat = json.loads(feat)
                        except Exception:
                            feat = {}
                    if feat:
                        st.markdown("**Top Features**")
                        feat_df = pd.DataFrame(
                            [(k, round(v, 4)) for k, v in feat.items() if v != 0],
                            columns=["Feature", "Value"],
                        ).sort_values("Value", ascending=False).head(10)
                        st.dataframe(feat_df, use_container_width=True)


if __name__ == "__main__":
    main()
else:
    main()
