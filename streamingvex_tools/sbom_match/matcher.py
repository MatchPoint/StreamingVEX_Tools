"""Firmware version normalization and catalog index matching."""

from __future__ import annotations

import re
from typing import Any

from streamingvex_tools.sbom_match.parser import SbomComponent


def normalize_firmware_version(version: str | None) -> str:
    if not version:
        return ""
    v = version.lower().strip()
    for prefix in ("edk2-stable", "edk2_stable", "stable-"):
        if prefix in v:
            tail = v.split(prefix, 1)[-1]
            digits = re.sub(r"[^0-9]", "", tail)
            if digits:
                return digits
    return re.sub(r"[^a-z0-9]+", "", v)


def find_index_matches(index: list[dict[str, Any]], comp: SbomComponent) -> list[dict[str, Any]]:
    if comp.purl:
        hits = [e for e in index if e.get("active", True) and e.get("product_purl") == comp.purl]
        if hits:
            return hits
    if comp.cpe:
        hits = [e for e in index if e.get("active", True) and e.get("product_cpe") == comp.cpe]
        if hits:
            return hits
    hits: list[dict[str, Any]] = []
    norm_version = normalize_firmware_version(comp.version)
    for entry in index:
        if not entry.get("active", True):
            continue
        if comp.name and entry.get("product_name") != comp.name:
            continue
        if comp.version:
            ev = entry.get("product_version")
            if ev != comp.version and normalize_firmware_version(ev) != norm_version:
                continue
        hits.append(entry)

    if comp.supplier and len(hits) > 1:
        supplier_hits = [
            e
            for e in hits
            if e.get("supplier_display_name") == comp.supplier or e.get("software_vendor_name") == comp.supplier
        ]
        if supplier_hits:
            hits = supplier_hits
    return hits


def best_index_match(hits: list[dict[str, Any]], comp: SbomComponent) -> dict[str, Any] | None:
    if not hits:
        return None

    def rank(entry: dict[str, Any]) -> tuple[int, int]:
        direct = 0 if entry.get("publisher_relationship") == "supplier_direct" else 1
        version_match = 0 if comp.version and entry.get("product_version") == comp.version else 1
        return (direct, version_match)

    return sorted(hits, key=rank)[0]
