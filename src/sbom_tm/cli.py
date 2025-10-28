from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .config import get_settings
from .context_generator import generate_context_file
from .rule_engine import RuleEngine
from .service import ScanService

app = typer.Typer(help="SBOM threat modeller")


@app.command()
def scan(
    path: Annotated[
        Optional[str],
        typer.Argument(
            exists=True,
            readable=True,
            help="Path to project directory for SBOM generation",
        ),
    ] = None,
    sbom: Annotated[
        Optional[Path],
        typer.Option(
            "--sbom",
            exists=True,
            readable=True,
            help="Path to CycloneDX SBOM file",
        ),
    ] = None,
    project: Annotated[
        str,
        typer.Option("--project", "-p", help="Project identifier"),
    ] = "default",
    context: Annotated[
        Optional[Path],
        typer.Option(
            "--context",
            exists=True,
            readable=True,
            help="Optional service context mapping JSON",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(help="Use Trivy offline scan mode"),
    ] = False,
) -> None:
    temp_sbom: Optional[Path] = None

    project_dir: Optional[Path] = Path(path).expanduser().resolve() if path else None

    if sbom is None and project_dir is None:
        typer.echo("Please provide either --sbom <path> or --path <path>")
        return
    if sbom is None:
        import shutil
        import subprocess
        import tempfile

        if project_dir is None:
            raise typer.BadParameter("--path is required when generating an SBOM automatically")

        if shutil.which("syft") is None:
            raise typer.BadParameter("syft not found. Install syft or provide --sbom <path>.")

        typer.echo("[SBOM-TM] generating SBOM using syft...")
        proc = subprocess.run(
            ["syft", str(project_dir), "-o", "cyclonedx-json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            typer.echo(f"syft failed: {proc.stderr.strip()}")
            raise typer.Exit(code=1)

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(proc.stdout.encode("utf-8"))
        tf.flush()
        tf.close()
        temp_sbom = Path(tf.name)
        sbom = temp_sbom

    if sbom is None:
        raise typer.BadParameter("Unable to resolve SBOM path")

    settings = get_settings()

    if context is None:
        generated_context = generate_context_file(
            sbom_path=sbom,
            project_dir=project_dir,
            project_name=project,
            output_dir=settings.cache_dir / "generated_contexts",
        )
        typer.echo(f"[SBOM-TM] generated context file: {generated_context}")
        context = generated_context

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
