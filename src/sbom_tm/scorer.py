from __future__ import annotations

from typing import Any, Dict

EXPLOITABILITY_MAP = {
    "NONE": 0.0,
    "PROOF_OF_CONCEPT": 0.6,
    "ACTIVE": 1.0,
    "ACTIVE_EXPLOIT": 1.0,
}

VALUE_MAP = {
    "low": 0.2,
    "medium": 0.5,
    "high": 1.0,
}

EXPOSURE_DEFAULT = 0.3


def compute_score(
    vulnerability: Dict[str, Any],
    context: Dict[str, Any],
    factors: Dict[str, float],
    pattern_multiplier: float = 1.0,
) -> float:
    cvss = _safe_float(vulnerability.get("CVSS")) or vulnerability.get("cvss")
    if isinstance(cvss, dict):
        cvss = _safe_float(cvss.get("Score")) or _safe_float(cvss.get("score"))
    severity_score = (cvss or 0.0) / 10.0

    exploit_maturity = vulnerability.get("Exploitability") or vulnerability.get("exploit_maturity")
    exploitability = EXPLOITABILITY_MAP.get(str(exploit_maturity or "NONE").upper(), 0.0)

    value_metric = context.get("value_metric", "medium")
    asset_value = VALUE_MAP.get(str(value_metric).lower(), 0.5)

    exposure = context.get("exposure", {}).get("internet", context.get("internet_exposed"))
    if exposure is None:
        exposure = EXPOSURE_DEFAULT
    elif isinstance(exposure, bool):
        exposure = 1.0 if exposure else 0.3
    else:
        exposure = float(exposure)

    cvss_weight = factors.get("cvss_weight", 0.5)
    exploitability_weight = factors.get(
        "exploitability_weight", factors.get("exploit_maturity_weight", 0.3)
    )
    asset_value_weight = factors.get("asset_value_weight", 0.15)
    exposure_weight = factors.get("exposure_weight", 0.05)

    baseline = (
        cvss_weight * severity_score
        + exploitability_weight * exploitability
        + asset_value_weight * asset_value
        + exposure_weight * exposure
    )

    score = 100.0 * min(1.0, baseline * pattern_multiplier)
    return round(score, 2)


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
