from __future__ import annotations

from pathlib import Path
from typing import Optional, Annotated

import typer

from .config import get_settings
from .rule_engine import RuleEngine
from .service import ScanService

app = typer.Typer(help="SBOM threat modeller")


@app.command()
def scan(
    path: Annotated[Optional[str], typer.Argument(exists=True, readable=True, help="Path to Project directory to generate SBOM from")] = None,
    sbom: Annotated[Optional[Path], typer.Option(exists=True, readable=True, help="Path to CycloneDX SBOM file")] = None,
    project: Annotated[str, typer.Option("--project", "-p", help="Project identifier")] = "default",
    context: Annotated[Optional[Path], typer.Option(exists=True, readable=True, help="Optional service context mapping JSON")] = None,
    offline: Annotated[bool, typer.Option(help="Use Trivy offline scan mode")] = False,
) -> None:
    temp_sbom: Optional[Path] = None
    import shutil
    import subprocess
    import tempfile

    if sbom is None and path is None:
        typer.echo("Please provide either --sbom <path> or --path <path>")
        return
    if sbom is None:
        if shutil.which("syft") is None:
            raise typer.BadParameter("syft not found in PATH. Install syft or provide --sbom <path>.")

        typer.echo("[SBOM-TM] generating SBOM using syft...")
        assert path is not None
        proc = subprocess.run(["syft", str(path), "-o", "cyclonedx-json"], check=False, capture_output=True, text=True)
        if proc.returncode != 0:
            typer.echo(f"syft failed: {proc.stderr.strip()}")
            raise typer.Exit(code=1)

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(proc.stdout.encode("utf-8"))
        tf.flush()
        tf.close()
        temp_sbom = Path(tf.name)
        sbom = temp_sbom

    typer.echo(f"[SBOM-TM] scanning SBOM: {sbom}")
    service = ScanService()
    result = service.run(sbom_path=sbom, project=project, context_path=context, offline=offline)
    typer.echo(
        f"[SBOM-TM] project={result.project} components={result.component_count}"
        f" vulns={result.vulnerability_count} threats={result.threat_count}"
    )
    typer.echo(f"[SBOM-TM] json report: {result.json_report}")
    typer.echo(f"[SBOM-TM] html report: {result.html_report}")

    if temp_sbom is not None:
        try:
            temp_sbom.unlink()
        except Exception:
            pass


@app.command()
def rules() -> None:
    settings = get_settings()
    engine = RuleEngine.from_directory(settings.rules_dir)
    typer.echo("Loaded rules:")
    for rule in engine.rules:
        typer.echo(f"- {rule.id}: {rule.description}")


@app.command()
def serve(
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8000,
) -> None:
    from uvicorn import run

    from .api import build_app

    typer.echo(f"[SBOM-TM] starting API on http://{host}:{port}")
    run(build_app(), host=host, port=port)
