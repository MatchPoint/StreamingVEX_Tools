"""Component role and gap classification."""

from __future__ import annotations

from typing import Any

from streamingvex_tools.sbom_match.parser import SbomComponent

_PRIMARY_TYPES = frozenset({"application", "firmware", "operating-system", "device", "container"})


def _names_match(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


def _components_match(left: SbomComponent, right: SbomComponent) -> bool:
    if left.purl and right.purl and left.purl == right.purl:
        return True
    if not _names_match(left.name, right.name):
        return False
    if left.version and right.version and left.version != right.version:
        return False
    return True


def mark_primary_component(
    components: list[SbomComponent],
    *,
    metadata_component: SbomComponent | None = None,
) -> None:
    if not components and metadata_component is None:
        return
    primary_indices: set[int] = set()
    meta = metadata_component
    if meta is not None:
        for i, comp in enumerate(components):
            if _components_match(comp, meta):
                primary_indices.add(i)
                break
        if not primary_indices:
            components.insert(0, SbomComponent(
                name=meta.name,
                version=meta.version,
                purl=meta.purl,
                supplier=meta.supplier,
                cpe=meta.cpe,
                component_type=meta.component_type or "firmware",
                component_role="primary",
            ))
            primary_indices.add(0)
    elif len(components) == 1:
        primary_indices.add(0)
    else:
        for i, comp in enumerate(components):
            if comp.component_type in _PRIMARY_TYPES:
                primary_indices.add(i)
                break
        if not primary_indices:
            primary_indices.add(0)
    for i, comp in enumerate(components):
        comp.component_role = "primary" if i in primary_indices else "dependency"
