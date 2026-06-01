"""Tests for streamingvex-sbom-match CLI logic."""

from __future__ import annotations

import json
from pathlib import Path

from streamingvex_tools.sbom_match.matcher import find_index_matches, normalize_firmware_version
from streamingvex_tools.sbom_match.parser import SbomComponent
from streamingvex_tools.sbom_match.report import build_sbom_match_report


def test_normalize_firmware_version() -> None:
    assert normalize_firmware_version("edk2-stable202508") == "202508"


def test_build_report_with_fixture() -> None:
    sbom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "EDK II", "version": "edk2-stable202508", "type": "firmware"}},
        "components": [
            {"name": "EDK II", "version": "edk2-stable202508", "purl": "pkg:generic/edk2@edk2-stable202508", "type": "firmware"},
            {"name": "openssl", "version": "3.5.1", "purl": "pkg:generic/openssl@3.5.1"},
        ],
    }
    index = [
        {
            "catalog_source_id": 1,
            "product_name": "EDK II",
            "product_version": "edk2-stable202508",
            "product_purl": "pkg:generic/edk2@edk2-stable202508",
            "publisher_relationship": "third_party",
            "active": True,
        },
        {
            "catalog_source_id": 2,
            "product_name": "openssl",
            "product_version": "3.5.1",
            "product_purl": "pkg:generic/openssl@3.5.1",
            "publisher_relationship": "supplier_direct",
            "active": True,
        },
    ]
    report = build_sbom_match_report(sbom, index)
    assert report["matched_count"] == 2
    assert report["matches"][0]["priority"] == "critical"


def test_find_index_matches_by_purl() -> None:
    comp = SbomComponent(name="openssl", version="3.5.1", purl="pkg:generic/openssl@3.5.1", supplier=None, cpe=None)
    index = [{"catalog_source_id": 2, "product_purl": "pkg:generic/openssl@3.5.1", "active": True}]
    hits = find_index_matches(index, comp)
    assert len(hits) == 1
