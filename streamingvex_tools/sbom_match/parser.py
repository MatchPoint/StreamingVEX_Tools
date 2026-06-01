"""Parse SBOM documents for client-side catalog matching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SbomComponent:
    name: str
    version: str | None
    purl: str | None
    supplier: str | None
    cpe: str | None
    component_role: str = "dependency"
    component_type: str | None = None
    bom_ref: str | None = None


def _supplier_from_cdx(comp: dict[str, Any]) -> str | None:
    supplier = comp.get("supplier") or comp.get("manufacturer")
    if isinstance(supplier, dict):
        return supplier.get("name")
    if isinstance(supplier, str):
        return supplier
    return None


def _cpe_from_cdx(comp: dict[str, Any]) -> str | None:
    raw = comp.get("cpe")
    if isinstance(raw, str) and raw.startswith("cpe:"):
        return raw
    for p in comp.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == "cpe" and p.get("value"):
            return str(p["value"])
    return None


def parse_cyclonedx(data: dict[str, Any]) -> list[SbomComponent]:
    out: list[SbomComponent] = []
    for comp in data.get("components") or []:
        if not isinstance(comp, dict):
            continue
        purls = comp.get("purl") or comp.get("bom-ref")
        purl = purls if isinstance(purls, str) and purls.startswith("pkg:") else None
        comp_type = comp.get("type")
        out.append(
            SbomComponent(
                name=str(comp.get("name") or comp.get("bom-ref") or "unknown"),
                version=comp.get("version"),
                purl=purl,
                supplier=_supplier_from_cdx(comp),
                cpe=_cpe_from_cdx(comp),
                component_type=str(comp_type) if comp_type else None,
                bom_ref=str(comp["bom-ref"]) if comp.get("bom-ref") else None,
            )
        )
    return out


def cyclonedx_metadata_component(data: dict[str, Any]) -> SbomComponent | None:
    meta = (data.get("metadata") or {}).get("component")
    if not isinstance(meta, dict) or not meta.get("name"):
        return None
    purl_raw = meta.get("purl")
    purl = purl_raw if isinstance(purl_raw, str) and purl_raw.startswith("pkg:") else None
    comp_type = meta.get("type")
    return SbomComponent(
        name=str(meta["name"]),
        version=meta.get("version"),
        purl=purl,
        supplier=_supplier_from_cdx(meta),
        cpe=_cpe_from_cdx(meta),
        component_type=str(comp_type) if comp_type else None,
        component_role="primary",
    )


def parse_sbom(data: dict[str, Any]) -> tuple[str, list[SbomComponent]]:
    if "components" in data and "bomFormat" in data:
        return "cyclonedx", parse_cyclonedx(data)
    raise ValueError("unsupported SBOM format (use CycloneDX JSON)")
