from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .context_loader import ServiceContext


@dataclass(slots=True)
class Rule:
    id: str
    description: str
    conditions: List[Dict[str, Any]]
    result: Dict[str, Any]
    score_factors: Dict[str, float]


class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    @classmethod
    def from_directory(cls, directory: Path) -> "RuleEngine":
        rules: List[Rule] = []
        for path in sorted(directory.glob("*.json")):
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if isinstance(payload, dict):
                payload = [payload]
            for entry in payload:
                rules.append(
                    Rule(
                        id=entry["id"],
                        description=entry.get("description", ""),
                        conditions=list(entry.get("conditions", [])),
                        result=entry.get("result", {}),
                        score_factors=entry.get("score_factors", {}),
                    )
                )
        return cls(rules)

    def evaluate(
        self,
        component: Dict[str, Any],
        vulnerability: Dict[str, Any],
        service: Optional[ServiceContext],
    ) -> Iterable[Dict[str, Any]]:
        context = {
            "component": component,
            "vuln": vulnerability,
            "context": asdict(service) if service else {},
        }
        for rule in self.rules:
            if all(_condition_matches(condition, context) for condition in rule.conditions):
                hypothesis = {
                    "rule_id": rule.id,
                    "description": rule.description,
                    "pattern": rule.result.get("pattern", []),
                    "objective": rule.result.get("objective", []),
                    "recommendations": rule.result.get("recommendations", []),
                    "pattern_multiplier": rule.result.get("pattern_multiplier", 1.0),
                    "score_factors": rule.score_factors,
                }
                yield hypothesis


def _condition_matches(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    if not condition:
        return True
    field, value = next(iter(condition.items()))
    actual = _dig_value(context, field)
    if isinstance(value, dict):
        for operator, expected in value.items():
            if not _compare(operator, actual, expected):
                return False
        return True
    return actual == value


def _dig_value(payload: Dict[str, Any], field: str) -> Any:
    current: Any = payload
    for token in field.split("."):
        if isinstance(current, dict):
            current = current.get(token)
        else:
            return None
    return current


def _compare(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "gte":
        return actual is not None and actual >= expected
    if operator == "lte":
        return actual is not None and actual <= expected
    if operator == "gt":
        return actual is not None and actual > expected
    if operator == "lt":
        return actual is not None and actual < expected
    if operator == "in":
        return actual in expected if isinstance(expected, (list, set, tuple)) else False
    if operator == "contains":
        if isinstance(actual, (list, set, tuple)):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False
    return False
