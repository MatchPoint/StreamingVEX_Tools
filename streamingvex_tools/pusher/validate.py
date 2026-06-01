"""Check whether a VEX payload has enough metadata for StreamingVEX catalog indexing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from streamingvex_tools.metadata import VexProductMetadata, detect_format, extract_metadata
from streamingvex_tools.vex_encryption import parse_encrypted_payload, resolve_content_encoding


@dataclass
class CatalogReadinessResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    content_encoding: str = "json"
    format_name: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    product_purl: str | None = None
    product_cpe: str | None = None
    product_name_source: str | None = None
    product_version_source: str | None = None
    product_purl_source: str | None = None
    product_cpe_source: str | None = None
    software_vendor_name: str | None = None
    software_vendor_name_source: str | None = None
    extracted: VexProductMetadata | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "content_encoding": self.content_encoding,
            "format_name": self.format_name,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "product_purl": self.product_purl,
            "product_cpe": self.product_cpe,
            "software_vendor_name": self.software_vendor_name,
            "product_name_source": self.product_name_source,
            "product_version_source": self.product_version_source,
            "product_purl_source": self.product_purl_source,
            "product_cpe_source": self.product_cpe_source,
            "software_vendor_name_source": self.software_vendor_name_source,
        }


def _pick(
    envelope: str | None,
    meta: str | None,
    *,
    envelope_label: str = "envelope",
    meta_label: str = "vex",
) -> tuple[str | None, str | None]:
    if envelope:
        return envelope, envelope_label
    if meta:
        return meta, meta_label
    return None, None


def _validate_format(data: dict[str, Any], format_name: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if format_name == "openvex":
        if "statements" not in data or not isinstance(data["statements"], list):
            errors.append("missing or invalid 'statements' array")
        else:
            for i, stmt in enumerate(data["statements"]):
                if isinstance(stmt, dict) and "vulnerability" not in stmt:
                    errors.append(f"statement[{i}] missing 'vulnerability'")
    elif format_name == "csaf":
        doc = data.get("document")
        if not isinstance(doc, dict):
            errors.append("missing document object")
        else:
            if "tracking" not in doc:
                errors.append("document.tracking required")
        if "vulnerabilities" not in data or not isinstance(data["vulnerabilities"], list):
            errors.append("vulnerabilities[] required")
    return errors, warnings


def validate_vex_for_catalog(
    vex_document: dict[str, Any],
    *,
    envelope_product_name: str | None = None,
    envelope_product_version: str | None = None,
    envelope_purl: str | None = None,
    envelope_cpe: str | None = None,
    envelope_software_vendor_name: str | None = None,
    content_encoding: str | None = None,
    supplier_display_name: str | None = None,
    require_software_vendor_name: bool = False,
) -> CatalogReadinessResult:
    errors: list[str] = []
    warnings: list[str] = []
    encoding = resolve_content_encoding(vex_document, declared=content_encoding)
    meta: VexProductMetadata | None = None
    format_name: str | None = None

    if encoding == "encrypted":
        try:
            parse_encrypted_payload(vex_document)
        except ValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(part) for part in err.get("loc", ()))
                msg = err.get("msg", "invalid field")
                errors.append(f"encrypted wrapper{('.' + loc) if loc else ''}: {msg}")
        format_name = "encrypted"
        if not envelope_product_name:
            errors.append(
                "product_name required in config/envelope for encrypted VEX "
                "(StreamingVEX cannot parse ciphertext server-side)"
            )
        if not envelope_product_version:
            errors.append(
                "product_version required in config/envelope for encrypted VEX "
                "(StreamingVEX cannot parse ciphertext server-side)"
            )
        if require_software_vendor_name and not envelope_software_vendor_name:
            errors.append(
                "software_vendor_name required in config/envelope for encrypted VEX "
                "(StreamingVEX cannot parse ciphertext server-side)"
            )
    else:
        format_name = detect_format(vex_document)
        if format_name is None:
            errors.append(
                "unrecognized VEX format (expected OpenVEX, CSAF, CycloneDX, SPDX, or encrypted wrapper)"
            )
        else:
            fmt_errors, fmt_warnings = _validate_format(vex_document, format_name)
            errors.extend(fmt_errors)
            warnings.extend(fmt_warnings)
            meta = extract_metadata(vex_document)

    product_name, product_name_source = _pick(
        envelope_product_name,
        meta.product_name if meta else None,
    )
    if product_name is None and supplier_display_name:
        product_name = supplier_display_name
        product_name_source = "supplier_display_name"
        warnings.append(
            "product_name not found in VEX or envelope; server would fall back to supplier display name "
            f"({supplier_display_name!r})"
        )
    elif product_name is None:
        errors.append(
            "product_name missing — add product_name to pusher.config.json or ensure the VEX document "
            "includes product metadata (CSAF product_tree, OpenVEX product PURL, etc.)"
        )

    product_version, product_version_source = _pick(
        envelope_product_version,
        meta.product_version if meta else None,
    )
    if product_version is None and encoding == "json":
        warnings.append(
            "product_version not found in VEX or envelope; catalog entry will have a null version "
            "(SBOM auto-matching and version-specific subscriptions may not work)"
        )

    product_purl, product_purl_source = _pick(
        envelope_purl,
        meta.product_purl if meta else None,
    )
    product_cpe, product_cpe_source = _pick(
        envelope_cpe,
        meta.product_cpe if meta else None,
    )
    software_vendor_name, software_vendor_name_source = _pick(
        envelope_software_vendor_name,
        meta.software_vendor if meta else None,
    )

    if encoding == "json" and not product_purl and not product_cpe:
        warnings.append(
            "no product_purl or product_cpe resolved; SBOM-driven subscription matching may be limited"
        )

    if (
        meta
        and envelope_product_name
        and meta.product_name
        and envelope_product_name != meta.product_name
    ):
        warnings.append(
            f"envelope product_name ({envelope_product_name!r}) overrides VEX value ({meta.product_name!r})"
        )
    if (
        meta
        and envelope_product_version
        and meta.product_version
        and envelope_product_version != meta.product_version
    ):
        warnings.append(
            "envelope product_version "
            f"({envelope_product_version!r}) overrides VEX value ({meta.product_version!r})"
        )

    ok = not errors
    return CatalogReadinessResult(
        ok=ok,
        errors=errors,
        warnings=warnings,
        content_encoding=encoding,
        format_name=format_name,
        product_name=product_name,
        product_version=product_version,
        product_purl=product_purl,
        product_cpe=product_cpe,
        software_vendor_name=software_vendor_name,
        product_name_source=product_name_source,
        product_version_source=product_version_source,
        product_purl_source=product_purl_source,
        product_cpe_source=product_cpe_source,
        software_vendor_name_source=software_vendor_name_source,
        extracted=meta,
    )


def encrypted_metadata_cli_help(*, include_encrypt_workflow: bool = True) -> str:
    lines = [
        "",
        "Encrypted VEX requires catalog metadata on the push envelope (config or CLI flags):",
        "  --product-name \"My Product\"",
        "  --product-version \"1.0.0\"",
        "  --software-vendor-name \"My Vendor\"",
        "  --product-cpe \"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*\"   (optional)",
        "  --product-purl \"pkg:generic/my-product@1.0.0\"                     (optional)",
    ]
    if include_encrypt_workflow:
        lines.extend(
            [
                "",
                "Or push cleartext and let the pusher validate, extract metadata, and encrypt:",
                "  --encrypt --encryption-key-file ./vex-aes256.key --encryption-key-id release-202411",
            ]
        )
    return "\n".join(lines)


def format_readiness_report(result: CatalogReadinessResult) -> str:
    lines = ["Catalog readiness: OK" if result.ok else "Catalog readiness: FAILED"]
    if result.format_name:
        lines.append(f"  format: {result.format_name}")
    lines.append(f"  content_encoding: {result.content_encoding}")

    def _field(label: str, value: str | None, source: str | None) -> None:
        if value is None:
            lines.append(f"  {label}: (missing)")
        else:
            suffix = f" (from {source})" if source else ""
            lines.append(f"  {label}: {value}{suffix}")

    _field("product_name", result.product_name, result.product_name_source)
    _field("product_version", result.product_version, result.product_version_source)
    if result.software_vendor_name or result.content_encoding == "encrypted":
        _field("software_vendor_name", result.software_vendor_name, result.software_vendor_name_source)
    if result.product_purl:
        _field("product_purl", result.product_purl, result.product_purl_source)
    if result.product_cpe:
        _field("product_cpe", result.product_cpe, result.product_cpe_source)

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {item}" for item in result.warnings)
    if result.errors:
        lines.append("")
        lines.append("Errors:")
        lines.extend(f"  - {item}" for item in result.errors)
        if result.content_encoding == "encrypted":
            lines.append(encrypted_metadata_cli_help())
    return "\n".join(lines)
