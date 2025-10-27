from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .config import get_settings
from .rule_engine import RuleEngine
from .service import ScanService

app = typer.Typer(help="SBOM threat modeller")


@app.command()
def scan(
    sbom: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to CycloneDX SBOM file"
    ),
    project: str = typer.Option("default", "--project", "-p", help="Project identifier"),
    context: Optional[Path] = typer.Option(
        None, "--context", exists=True, readable=True, help="Optional service context mapping JSON"
    ),
    offline: bool = typer.Option(False, "--offline", help="Use Trivy offline scan mode"),
) -> None:
    typer.echo(f"[SBOM-TM] scanning SBOM: {sbom}")
    service = ScanService()
    result = service.run(sbom_path=sbom, project=project, context_path=context, offline=offline)
    typer.echo(
        f"[SBOM-TM] project={result.project} components={result.component_count}"
        f" vulns={result.vulnerability_count} threats={result.threat_count}"
    )
    typer.echo(f"[SBOM-TM] json report: {result.json_report}")
    typer.echo(f"[SBOM-TM] html report: {result.html_report}")


@app.command()
def rules() -> None:
    settings = get_settings()
    engine = RuleEngine.from_directory(settings.rules_dir)
    typer.echo("Loaded rules:")
    for rule in engine.rules:
        typer.echo(f"- {rule.id}: {rule.description}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    from uvicorn import run

    from .api import build_app

    typer.echo(f"[SBOM-TM] starting API on http://{host}:{port}")
    run(build_app(), host=host, port=port)
