from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass(slots=True)
class ParsedComponent:
    name: str
    version: Optional[str]
    purl: Optional[str]
    supplier: Optional[str]
    hashes: Dict[str, Any]
    properties: Dict[str, Any]


def load_sbom(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def iter_components(sbom: Dict[str, Any]) -> Iterable[ParsedComponent]:
    components = sbom.get("components", [])
    for component in components:
        yield ParsedComponent(
            name=component.get("name", "unknown"),
            version=component.get("version"),
            purl=component.get("purl"),
            supplier=component.get("supplier"),
            hashes={
                hash_obj.get("alg") or hash_obj.get("algorithm", ""): hash_obj.get("content")
                for hash_obj in component.get("hashes", [])
            },
            properties={
                prop.get("name"): prop.get("value") for prop in component.get("properties", [])
            },
        )


def load_components(path: Path) -> List[ParsedComponent]:
    sbom = load_sbom(path)
    return list(iter_components(sbom))
