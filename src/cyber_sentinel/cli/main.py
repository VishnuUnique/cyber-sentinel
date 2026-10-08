"""Cyber Sentinel CLI — Typer-based command-line interface."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from cyber_sentinel.utils.logging import setup_logging, get_logger

app = typer.Typer(
    name="cyber-sentinel",
    help="Intelligent Cyber Threat and Network Anomaly Detection Sentinel",
    add_completion=False,
)
console = Console()
logger = get_logger(__name__)

# Resolve the project root
_HERE = Path(__file__).resolve()
# src/cyber_sentinel/cli/main.py → project root is 3 dirs up from here
_PROJECT_ROOT = _HERE.parents[3]


def _scripts_dir() -> Path:
    return _PROJECT_ROOT / "scripts"


@app.command("generate-data")
def generate_data():
    """Generate synthetic demo data for training and testing."""
    setup_logging()
    script = _scripts_dir() / "generate_demo_data.py"
    console.print(f"[bold blue]Running:[/] python {script}")
    result = subprocess.run([sys.executable, str(script)], cwd=str(_PROJECT_ROOT))
    raise typer.Exit(result.returncode)


@app.command("train")
def train():
    """Train anomaly and classification models on synthetic data."""
    setup_logging()
    script = _scripts_dir() / "train_models.py"
    console.print(f"[bold blue]Running:[/] python {script}")
    result = subprocess.run([sys.executable, str(script)], cwd=str(_PROJECT_ROOT))
    raise typer.Exit(result.returncode)


@app.command("ingest")
def ingest(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input file (JSON, JSONL, CSV)"),
    max_risk: Optional[int] = typer.Option(None, "--max-risk", help="Policy threshold (0-100)"),
    output: str = typer.Option("text", "--output", "-o", help="Output format: json or text"),
):
    """Ingest telemetry records from a file and run detection."""
    setup_logging()
    from cyber_sentinel.ingestion.parser import TelemetryParser
    from cyber_sentinel.detection.pipeline import SentinelPipeline
    from cyber_sentinel.database.database import initialize_database, get_session
    from cyber_sentinel.database.repository import AlertRepository
    from cyber_sentinel.risk.policy import PolicyGuardrail
    from cyber_sentinel.config.settings import settings

    if not input_file.exists():
        console.print(f"[red]Error:[/] File not found: {input_file}")
        raise typer.Exit(1)

    initialize_database()
    repo = AlertRepository(session_factory=get_session)
    pipeline = SentinelPipeline(db_repo=repo)

    parser = TelemetryParser()
    records, parse_errors = parser.parse_file(str(input_file))

    if parse_errors:
        for err in parse_errors[:5]:
            console.print(f"[yellow]Parse warning:[/] {err}")

    console.print(f"[green]Parsed {len(records)} records from {input_file.name}")
    alerts = pipeline.process_batch(records)

    _print_alerts(alerts, output, console)

    stats = pipeline.get_stats()
    console.print(f"\n[bold]Stats:[/] processed={stats['records_processed']} "
                  f"rejected={stats['records_rejected']} alerts={len(alerts)}")

    threshold = max_risk if max_risk is not None else settings.risk.max_risk
    guardrail = PolicyGuardrail(max_risk=threshold)
    result = guardrail.evaluate(alerts)
    console.print(f"\n[bold]Policy ({threshold}):[/] {result.summary}")
    raise typer.Exit(result.exit_code)


@app.command("analyze")
def analyze(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input file (JSON, JSONL, CSV)"),
    max_risk: int = typer.Option(70, "--max-risk", help="Policy threshold (0-100)"),
    output: str = typer.Option("text", "--output", "-o", help="Output format: json or text"),
):
    """Analyze telemetry and apply risk policy (exits 0=pass, 1=breach)."""
    setup_logging()
    from cyber_sentinel.ingestion.parser import TelemetryParser
    from cyber_sentinel.detection.pipeline import SentinelPipeline
    from cyber_sentinel.risk.policy import PolicyGuardrail

    if not input_file.exists():
        console.print(f"[red]Error:[/] File not found: {input_file}")
        raise typer.Exit(1)

    pipeline = SentinelPipeline()
    parser = TelemetryParser()
    records, _ = parser.parse_file(str(input_file))
    alerts = pipeline.process_batch(records)

    _print_alerts(alerts, output, console)

    guardrail = PolicyGuardrail(max_risk=max_risk)
    result = guardrail.evaluate(alerts)

    if output == "json":
        console.print(json.dumps({
            "policy_passed": result.passed,
            "max_risk": max_risk,
            "max_observed_risk": result.max_observed_risk,
            "breach_count": len(result.breach_alerts),
            "summary": result.summary,
        }, indent=2))
    else:
        color = "green" if result.passed else "red"
        console.print(f"\n[bold {color}]{result.summary}[/]")

    raise typer.Exit(result.exit_code)


@app.command("dashboard")
def dashboard(
    port: int = typer.Option(8501, "--port", help="Streamlit port"),
):
    """Launch the Streamlit operator dashboard."""
    setup_logging()
    app_path = _PROJECT_ROOT / "src" / "cyber_sentinel" / "dashboard" / "app.py"
    console.print(f"[bold blue]Launching dashboard on port {port}...[/]")
    result = subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(port)],
        cwd=str(_PROJECT_ROOT),
    )
    raise typer.Exit(result.returncode)


@app.command("api")
def api(
    port: int = typer.Option(8000, "--port", help="API port"),
    host: str = typer.Option("0.0.0.0", "--host", help="API host"),
):
    """Launch the FastAPI server."""
    setup_logging()
    console.print(f"[bold blue]Starting API on {host}:{port}...[/]")
    result = subprocess.run(
        [
            sys.executable, "-m", "uvicorn",
            "cyber_sentinel.api.main:app",
            "--host", host,
            "--port", str(port),
            "--reload",
        ],
        cwd=str(_PROJECT_ROOT),
        env={**__import__("os").environ, "PYTHONPATH": str(_PROJECT_ROOT / "src")},
    )
    raise typer.Exit(result.returncode)


@app.command("evaluate")
def evaluate():
    """Evaluate model performance on synthetic test data."""
    setup_logging()
    script = _scripts_dir() / "evaluate_models.py"
    console.print(f"[bold blue]Running:[/] python {script}")
    result = subprocess.run([sys.executable, str(script)], cwd=str(_PROJECT_ROOT))
    raise typer.Exit(result.returncode)


@app.command("alerts")
def list_alerts(
    risk_min: int = typer.Option(0, "--risk-min", help="Minimum risk score filter"),
    limit: int = typer.Option(20, "--limit", help="Maximum number of alerts to show"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
):
    """Query and display alerts from the database."""
    setup_logging()
    from cyber_sentinel.database.database import initialize_database, get_session
    from cyber_sentinel.database.repository import AlertRepository

    initialize_database()
    repo = AlertRepository(session_factory=get_session)

    records = repo.list_alerts(skip=0, limit=limit, risk_min=float(risk_min), status=status)

    if not records:
        console.print("[yellow]No alerts found with the specified filters.[/]")
        raise typer.Exit(0)

    table = Table(title=f"Alerts (risk >= {risk_min}, limit={limit})")
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Source IP")
    table.add_column("Dest IP")
    table.add_column("Classification")
    table.add_column("Risk", justify="right")
    table.add_column("Band")
    table.add_column("Status")

    for r in records:
        ts = r.timestamp.isoformat()[:19] if r.timestamp else "?"
        band_color = {"Normal": "green", "Suspicious": "yellow", "Malicious": "red"}.get(r.risk_band, "white")
        table.add_row(
            ts,
            r.source_ip,
            r.dest_ip or "-",
            r.classification,
            f"{r.risk_score:.1f}",
            f"[{band_color}]{r.risk_band}[/{band_color}]",
            r.status,
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(records)} alert(s)[/]")


def _print_alerts(alerts, output: str, con: Console) -> None:
    """Print alerts in the requested format."""
    if output == "json":
        data = []
        for a in alerts:
            data.append({
                "alert_id": a.alert_id,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "classification": a.classification,
                "risk_score": round(a.risk_score, 2),
                "risk_band": a.risk_band,
                "anomaly_score": round(a.anomaly_score, 2),
                "evidence_count": len(a.evidence_features),
            })
        con.print(json.dumps(data, indent=2))
    else:
        if not alerts:
            con.print("[dim]No alerts generated[/]")
            return
        table = Table(title=f"Detection Results ({len(alerts)} alerts)")
        table.add_column("Source IP")
        table.add_column("Destination IP")
        table.add_column("Classification")
        table.add_column("Risk", justify="right")
        table.add_column("Band")
        table.add_column("Anomaly")
        for a in alerts:
            band_color = {"Normal": "green", "Suspicious": "yellow", "Malicious": "red"}.get(a.risk_band, "white")
            table.add_row(
                a.source_ip,
                a.dest_ip or "-",
                a.classification,
                f"{a.risk_score:.1f}",
                f"[{band_color}]{a.risk_band}[/{band_color}]",
                f"{a.anomaly_score:.1f}",
            )
        con.print(table)


if __name__ == "__main__":
    app()
