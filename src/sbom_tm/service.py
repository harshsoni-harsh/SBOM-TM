from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlmodel import select

from . import sbom_loader, trivy_client
from .config import get_settings
from .context_loader import ServiceContext, load_context
from .models import Component, ProjectScan, Threat, Vulnerability
from .report_builder import write_html_report, write_json_report
from .rule_engine import RuleEngine
from .scorer import compute_score
from .storage import session_scope
from .threatintel_enricher import enrich_with_threatintel



@dataclass(slots=True)
class ScanResult:
    project: str
    component_count: int
    vulnerability_count: int
    threat_count: int
    json_report: Path
    html_report: Path


class ScanService:
    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self.rule_engine = RuleEngine.from_directory(settings.rules_dir)

    def run(
        self,
        sbom_path: Path,
        project: str,
        context_path: Optional[Path] = None,
        offline: bool = False,
    ) -> ScanResult:
        components = sbom_loader.load_components(sbom_path)
        service_map = load_context(context_path)
        try:
            trivy_report = trivy_client.scan_sbom(sbom_path, offline=offline)
        except trivy_client.TrivyError as exc:
            fallback = self.settings.cache_dir / "sample_trivy_report.json"
            if fallback.exists():
                with fallback.open("r", encoding="utf-8") as fh:
                    trivy_report = json.load(fh)
            else:
                raise exc
        vuln_index = trivy_client.extract_vulnerabilities(trivy_report)

        threats_payload: List[dict] = []
        vulnerability_count = 0

        with session_scope() as session:
            scan = ProjectScan(project=project, sbom_path=str(sbom_path))
            session.add(scan)
            session.flush()

            for parsed in components:
                component_record = Component(
                    scan_id=scan.id,
                    name=parsed.name,
                    version=parsed.version,
                    purl=parsed.purl,
                    supplier=parsed.supplier,
                    hashes=parsed.hashes or None,
                    properties=parsed.properties or None,
                )
                session.add(component_record)
                session.flush()

                service_context = self._resolve_context(parsed, service_map)
                component_dict = {
                    "name": parsed.name,
                    "version": parsed.version,
                    "purl": parsed.purl,
                    "supplier": parsed.supplier,
                    "hashes": parsed.hashes,
                    "properties": parsed.properties,
                }

                raw_vulnerabilities = list(
                    trivy_client.vulnerabilities_for_component(
                        parsed.purl,
                        parsed.name,
                        vuln_index,
                    )
                )

                if not raw_vulnerabilities:
                    continue

                enriched_payload = enrich_with_threatintel(
                    [
                        {
                            "component": component_dict,
                            "vulnerabilities": raw_vulnerabilities,
                        }
                    ]
                )
                enriched_vulnerabilities = (
                    enriched_payload[0].get("vulnerabilities", raw_vulnerabilities)
                    if enriched_payload
                    else raw_vulnerabilities
                )

                for enriched_vuln in enriched_vulnerabilities:
                    vulnerability_count += 1

                    vuln_record = Vulnerability(
                        component_id=component_record.id,
                        cve=_extract(enriched_vuln, ["VulnerabilityID", "cve"]),
                        severity=_extract(enriched_vuln, ["Severity", "severity"]),
                        cvss=_extract_cvss(enriched_vuln),
                        exploit_maturity=_extract(enriched_vuln, ["Exploitability", "exploit_maturity"]),
                        published=_extract(enriched_vuln, ["PublishedDate", "published"]),
                        raw=enriched_vuln,
                    )
                    session.add(vuln_record)
                    session.flush()

                    for hypothesis in self.rule_engine.evaluate(
                        component_dict,
                        enriched_vuln,
                        service_context,
                        threatintel=enriched_vuln.get("threatintel", {}),
                    ):
                        rule_severity = hypothesis.get("rule_severity", "medium")
                        severity_multiplier = {"low": 0.8, "medium": 1.0, "high": 1.2}.get(rule_severity, 1.0)

                        score = compute_score(
                            vulnerability=enriched_vuln,
                            context=self._context_dict(service_context),
                            factors=hypothesis.get("score_factors", {}),
                            pattern_multiplier=hypothesis.get("pattern_multiplier", 1.0)
                            * severity_multiplier,
                        )
                        threat_record = Threat(
                            project=project,
                            scan_id=scan.id,
                            vulnerability_id=vuln_record.id,
                            rule_id=hypothesis["rule_id"],
                            score=score,
                            hypothesis=self._build_hypothesis_payload(
                                component_dict,
                                enriched_vuln,
                                service_context,
                                hypothesis,
                                score,
                            ),
                        )
                        session.add(threat_record)
                        session.flush()

                        threat_export = dict(threat_record.hypothesis)
                        threat_export["score"] = score
                        threat_export["rule_id"] = threat_record.rule_id
                        threat_export["threat_id"] = threat_record.id
                        threats_payload.append(threat_export)

            json_path = self.settings.report_dir / f"{project}_report.json"
            write_json_report(threats_payload, json_path)
            html_path = write_html_report(threats_payload, project)

        return ScanResult(
            project=project,
            component_count=len(components),
            vulnerability_count=vulnerability_count,
            threat_count=len(threats_payload),
            json_report=json_path,
            html_report=html_path,
        )

    def list_threats(self, project: Optional[str] = None) -> List[Threat]:
        with session_scope() as session:
            statement = select(Threat)
            if project:
                statement = statement.where(Threat.project == project)
            return list(session.exec(statement))

    @staticmethod
    def _resolve_context(
        component: sbom_loader.ParsedComponent,
        mapping: Dict[str, ServiceContext],
    ) -> Optional[ServiceContext]:
        if component.purl and component.purl in mapping:
            return mapping[component.purl]
        if component.name and component.name in mapping:
            return mapping[component.name]
        return None

    @staticmethod
    def _context_dict(service_context: Optional[ServiceContext]) -> Dict[str, Any]:
        return asdict(service_context) if service_context else {}

    def _build_hypothesis_payload(
        self,
        component: Dict[str, Any],
        vulnerability: Dict[str, Any],
        service_context: Optional[ServiceContext],
        hypothesis: Dict[str, Any],
        score: float,
    ) -> Dict[str, Any]:
        context_dict = self._context_dict(service_context)
        return {
            "target": {
                "service": context_dict.get("service", "unknown"),
                "component": component,
            },
            "value": {
                "data_class": context_dict.get("data_class", []),
                "value_metric": context_dict.get("value_metric", "medium"),
            },
            "pattern": hypothesis.get("pattern", []),
            "objective": hypothesis.get("objective", []),
            "evidence": {
                "cve": _extract(vulnerability, ["VulnerabilityID", "cve"]),
                "severity": _extract(vulnerability, ["Severity", "severity"]),
                "cvss": _extract_cvss(vulnerability),
                "exploit_maturity": _extract(vulnerability, ["Exploitability", "exploit_maturity"]),
                "intel": vulnerability.get("threatintel", {}),
            },
            "recommended_actions": hypothesis.get("recommendations", []),
            "score": score,
            "status": "open",
        }


def _extract(payload: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return None


def _extract_cvss(payload: Dict[str, Any]) -> Optional[float]:
    cvss = payload.get("CVSS") or payload.get("cvss")
    if isinstance(cvss, (int, float)):
        return float(cvss)
    if isinstance(cvss, dict):
        score = cvss.get("nvd") or cvss.get("Score") or cvss.get("score")
        return _safe_float(score)
    score = payload.get("CVSSScore") or payload.get("cvssScore")
    return _safe_float(score)


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
