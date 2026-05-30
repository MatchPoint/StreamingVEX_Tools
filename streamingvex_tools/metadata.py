"""Extract product metadata from VEX documents (keep in sync with streamingvex/formats/metadata.py)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class VexProductMetadata:
    supplier_name: str | None
    software_vendor: str | None
    product_name: str | None
    product_version: str | None
    product_purl: str | None
    product_cpe: str | None
    format_name: str | None


def detect_format(data: dict[str, Any]) -> str | None:
    if data.get("streamingvex_encrypted_vex") == "1":
        return "encrypted"
    if "document" in data and isinstance(data.get("document"), dict):
        return "csaf"
    if "@context" in data:
        ctx = data["@context"]
        if isinstance(ctx, str) and "openvex" in ctx.lower():
            return "openvex"
    if "statements" in data:
        sts = data.get("statements")
        if isinstance(sts, list) and sts:
            first = sts[0]
            if isinstance(first, dict) and ("vulnerability" in first or "products" in first):
                return "openvex"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if data.get("spdxVersion"):
        return "spdx"
    return None


def _purl_from_openvex_product(prod: Any) -> str | None:
    if isinstance(prod, str):
        return prod if prod.startswith("pkg:") else None
    if isinstance(prod, dict):
        if "@id" in prod and str(prod["@id"]).startswith("pkg:"):
            return str(prod["@id"])
        ids = prod.get("identifiers") or {}
        if isinstance(ids, dict) and ids.get("purl"):
            return str(ids["purl"])
    return None


def _parse_purl(purl: str) -> tuple[str | None, str | None]:
    if not purl.startswith("pkg:"):
        return None, None
    rest = purl[4:]
    at = rest.rfind("@")
    version = rest[at + 1 :] if at >= 0 else None
    path = rest[:at] if at >= 0 else rest
    name = path.split("/")[-1] if "/" in path else path.split(":")[-1] if ":" in path else path
    return name or None, version or None


def _cpe_from_product_id(product_id: str | None) -> str | None:
    if not product_id or not product_id.startswith("pid-cpe_"):
        return None
    inner = product_id[8:].rstrip("_")
    parts = inner.split("_")
    if len(parts) >= 5 and parts[0] == "2.3":
        return f"cpe:2.3:{parts[1]}:{parts[2]}:{parts[3]}:{parts[4]}:*:*:*:*:*:*:*"
    return None


def _walk_csaf_branches(
    branches: list[Any],
    vendor: str | None = None,
    product: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    for branch in branches:
        if not isinstance(branch, dict):
            continue
        cat = branch.get("category")
        name = branch.get("name")
        if cat == "vendor" and name:
            vendor = str(name)
        elif cat == "product_name" and name:
            product = str(name)
        elif cat == "product_version" and name:
            prod = branch.get("product") or {}
            pid = prod.get("product_id") if isinstance(prod, dict) else None
            cpe = _cpe_from_product_id(str(pid) if pid else None)
            return vendor, product, str(name), cpe
        nested = branch.get("branches")
        if isinstance(nested, list):
            v, p, ver, cpe = _walk_csaf_branches(nested, vendor, product)
            if ver:
                return v, p, ver, cpe
            vendor, product = v or vendor, p or product
    return vendor, product, None, None


def extract_metadata(payload: dict[str, Any]) -> VexProductMetadata:
    fmt = detect_format(payload)
    supplier: str | None = None
    software_vendor: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    product_purl: str | None = None
    product_cpe: str | None = None

    if fmt == "openvex":
        supplier = payload.get("supplier") or payload.get("author")
        if isinstance(supplier, dict):
            supplier = supplier.get("name") or supplier.get("@id")
        software_vendor = str(supplier) if supplier else None
        for stmt in payload.get("statements") or []:
            if not isinstance(stmt, dict):
                continue
            for prod in stmt.get("products") or []:
                purl = _purl_from_openvex_product(prod)
                if purl:
                    product_purl = purl
                    pn, pv = _parse_purl(purl)
                    product_name = product_name or pn
                    product_version = product_version or pv
                    break
            if product_purl:
                break
    elif fmt == "csaf":
        document = payload.get("document") or {}
        publisher = document.get("publisher") or {}
        supplier = publisher.get("name") or publisher.get("namespace")
        tree = payload.get("product_tree") or {}
        branches = tree.get("branches") or []
        sv, pn, pv, cpe = _walk_csaf_branches(branches)
        software_vendor = sv
        product_name = pn
        product_version = pv
        product_cpe = cpe
        if not product_version:
            title = document.get("title") or ""
            if "edk2-stable" in title:
                product_version = title.split("edk2-stable")[-1].strip()

    if product_purl and not product_name:
        pn, pv = _parse_purl(product_purl)
        product_name = pn
        product_version = product_version or pv

    return VexProductMetadata(
        supplier_name=str(supplier) if supplier else None,
        software_vendor=software_vendor,
        product_name=product_name,
        product_version=product_version,
        product_purl=product_purl,
        product_cpe=product_cpe,
        format_name=fmt,
    )
