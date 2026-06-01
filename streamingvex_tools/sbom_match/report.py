"""Build SBOM match reports locally."""

from __future__ import annotations

from typing import Any

from streamingvex_tools.sbom_match.classify import mark_primary_component
from streamingvex_tools.sbom_match.matcher import best_index_match, find_index_matches
from streamingvex_tools.sbom_match.parser import cyclonedx_metadata_component, parse_sbom


def build_sbom_match_report(sbom: dict[str, Any], index_entries: list[dict[str, Any]]) -> dict[str, Any]:
    fmt, components = parse_sbom(sbom)
    meta = cyclonedx_metadata_component(sbom) if fmt == "cyclonedx" else None
    mark_primary_component(components, metadata_component=meta)

    matches: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    primary_component: dict[str, Any] | None = None

    for comp in components:
        if comp.component_role == "primary" and primary_component is None:
            primary_component = {
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
                "supplier": comp.supplier,
            }
        hits = find_index_matches(index_entries, comp)
        if hits:
            best = best_index_match(hits, comp)
            assert best is not None
            matches.append(
                {
                    "component_role": comp.component_role,
                    "priority": "critical" if comp.component_role == "primary" else "supplemental",
                    "sbom": {
                        "name": comp.name,
                        "version": comp.version,
                        "purl": comp.purl,
                        "supplier": comp.supplier,
                    },
                    "recommended_catalog_source_id": best["catalog_source_id"],
                    "catalog_matches": hits,
                }
            )
        else:
            gaps.append(
                {
                    "component_role": comp.component_role,
                    "sbom": {"name": comp.name, "version": comp.version, "purl": comp.purl, "supplier": comp.supplier},
                }
            )

    matches.sort(key=lambda m: (0 if m["priority"] == "critical" else 1, m["sbom"]["name"]))

    return {
        "sbom_format": fmt,
        "component_count": len(components),
        "primary_component": primary_component,
        "matched_count": len(matches),
        "gap_count": len(gaps),
        "matches": matches,
        "gaps": gaps,
    }
