#!/usr/bin/env python3
"""VEX Pusher — push signed supplier envelopes to a StreamingVEX server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx

from streamingvex_tools.envelope import SupplierPushEnvelope
from streamingvex_tools.pusher.config_loader import load_pusher_config
from streamingvex_tools.pusher.encrypt import encrypt_vex_document
from streamingvex_tools.pusher.encrypt_openpgp import (
    encrypt_vex_document_openpgp,
    load_passphrase,
)
from streamingvex_tools.pusher.recipients import fetch_encryption_recipients
from streamingvex_tools.pusher.validate import (
    CatalogReadinessResult,
    format_readiness_report,
    validate_vex_for_catalog,
)
from streamingvex_tools.vex_encryption import is_encrypted_payload, resolve_content_encoding


def _load_json(path: str | None) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    return json.loads(raw)


def _load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        return load_pusher_config(path)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def build_envelope(
    *,
    supplier_slug: str,
    vex_document: dict[str, Any],
    product_name: str | None,
    product_version: str | None,
    product_purl: str | None,
    product_cpe: str | None,
    software_vendor_name: str | None,
    signing_key_pem_path: str | None,
    content_encoding: str | None = None,
) -> SupplierPushEnvelope:
    encoding = content_encoding
    if encoding is None and is_encrypted_payload(vex_document):
        encoding = "encrypted"
    env = SupplierPushEnvelope(
        supplier_slug=supplier_slug,
        vex_document=vex_document,
        content_encoding=encoding or "json",
        product_name=product_name,
        product_version=product_version,
        product_purl=product_purl,
        product_cpe=product_cpe,
        software_vendor_name=software_vendor_name,
    )
    if signing_key_pem_path:
        env.sign_ed25519_pem(Path(signing_key_pem_path).read_bytes())
    return env


def push_envelope(
    base_url: str,
    api_key: str,
    envelope: SupplierPushEnvelope,
    idem_key: str | None,
) -> httpx.Response:
    url = base_url.rstrip("/") + "/v1/supplier/push"
    headers = {"X-Supplier-API-Key": api_key, "Content-Type": "application/json"}
    if idem_key:
        headers["Idempotency-Key"] = idem_key
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        return client.post(url, json=envelope.model_dump(), headers=headers)


def _envelope_product_fields(cfg: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    return {
        "envelope_product_name": cfg.get("product_name") or args.product_name,
        "envelope_product_version": cfg.get("product_version") or args.product_version,
        "envelope_purl": cfg.get("product_purl") or args.product_purl,
        "envelope_cpe": cfg.get("product_cpe") or args.product_cpe,
        "envelope_software_vendor_name": cfg.get("software_vendor_name") or args.software_vendor_name,
        "content_encoding": cfg.get("content_encoding") or args.content_encoding,
        "require_software_vendor_name": bool(
            cfg.get("software_vendor_name")
            or args.software_vendor_name
            or args.encrypt
            or getattr(args, "encrypt_openpgp", False)
        ),
    }


def _merge_fields_from_cleartext_validation(
    product_fields: dict[str, Any],
    clear_result: CatalogReadinessResult,
) -> dict[str, Any]:
    merged = dict(product_fields)
    if not merged.get("envelope_product_name") and clear_result.product_name:
        merged["envelope_product_name"] = clear_result.product_name
    if not merged.get("envelope_product_version") and clear_result.product_version:
        merged["envelope_product_version"] = clear_result.product_version
    if not merged.get("envelope_purl") and clear_result.product_purl:
        merged["envelope_purl"] = clear_result.product_purl
    if not merged.get("envelope_cpe") and clear_result.product_cpe:
        merged["envelope_cpe"] = clear_result.product_cpe
    if not merged.get("envelope_software_vendor_name") and clear_result.software_vendor_name:
        merged["envelope_software_vendor_name"] = clear_result.software_vendor_name
    merged["content_encoding"] = "encrypted"
    merged["require_software_vendor_name"] = True
    return merged


def _prepare_vex_document(
    vex_doc: dict[str, Any],
    *,
    args: argparse.Namespace,
    cfg: dict[str, Any],
    product_fields: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if getattr(args, "encrypt_openpgp", False):
        if is_encrypted_payload(vex_doc):
            raise SystemExit(
                "--encrypt-openpgp requires a cleartext VEX file. "
                "Remove the flag when pushing a pre-encrypted wrapper."
            )
        base_url = cfg.get("base_url") or args.base_url
        api_key = cfg.get("api_key") or args.api_key
        if not base_url or not api_key:
            raise SystemExit("--encrypt-openpgp requires base_url and api_key in config")
        priv_path = args.pgp_private_key_file or cfg.get("pgp_private_key_file")
        key_id = args.encryption_key_id or cfg.get("encryption_key_id")
        if not priv_path or not key_id:
            raise SystemExit(
                "--encrypt-openpgp requires --pgp-private-key-file and --encryption-key-id "
                "(or pgp_private_key_file / encryption_key_id in config)"
            )
        clear_fields = dict(product_fields)
        clear_fields["content_encoding"] = "json"
        clear_fields["require_software_vendor_name"] = False
        clear_result = validate_vex_for_catalog(vex_doc, **clear_fields)
        if not clear_result.ok:
            print(format_readiness_report(clear_result), file=sys.stderr)
            raise SystemExit(1)
        merged = _merge_fields_from_cleartext_validation(product_fields, clear_result)
        scope = args.encryption_recipients_scope or cfg.get("encryption_recipients_scope")
        recipients = fetch_encryption_recipients(
            base_url=base_url,
            api_key=api_key,
            scope=scope,
        )
        passphrase = load_passphrase(args.pgp_passphrase_file or cfg.get("pgp_passphrase_file"))
        encrypted_doc = encrypt_vex_document_openpgp(
            vex_doc,
            private_key_path=priv_path,
            passphrase=passphrase,
            recipients=recipients,
            key_id=key_id,
            plaintext_format=clear_result.format_name,
        )
        return encrypted_doc, merged

    if args.encrypt:
        if is_encrypted_payload(vex_doc):
            raise SystemExit(
                "--encrypt requires a cleartext VEX file. Remove --encrypt when pushing a pre-encrypted wrapper."
            )
        key_file = args.encryption_key_file or cfg.get("encryption_key_file")
        key_id = args.encryption_key_id or cfg.get("encryption_key_id")
        if not key_file or not key_id:
            raise SystemExit(
                "--encrypt requires --encryption-key-file and --encryption-key-id "
                "(or encryption_key_file / encryption_key_id in pusher.config.json)"
            )
        clear_fields = dict(product_fields)
        clear_fields["content_encoding"] = "json"
        clear_fields["require_software_vendor_name"] = False
        clear_result = validate_vex_for_catalog(vex_doc, **clear_fields)
        if not clear_result.ok:
            print(format_readiness_report(clear_result), file=sys.stderr)
            raise SystemExit(1)
        merged = _merge_fields_from_cleartext_validation(product_fields, clear_result)
        encrypted_doc = encrypt_vex_document(
            vex_doc,
            key_path=key_file,
            key_id=key_id,
            plaintext_format=clear_result.format_name,
        )
        return encrypted_doc, merged

    encoding = resolve_content_encoding(vex_doc, declared=product_fields.get("content_encoding"))
    fields = dict(product_fields)
    if encoding == "encrypted":
        fields["content_encoding"] = "encrypted"
        fields["require_software_vendor_name"] = True
    return vex_doc, fields


def _add_catalog_field_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        help="JSON config with optional product_name, product_version, product_purl, product_cpe, software_vendor_name",
    )
    parser.add_argument("--file", help="VEX JSON file (OpenVEX/CSAF); stdin if omitted")
    parser.add_argument("--product-name")
    parser.add_argument("--product-version")
    parser.add_argument("--product-purl")
    parser.add_argument("--product-cpe")
    parser.add_argument(
        "--software-vendor-name",
        help="Product supplier / software vendor (required on envelope for encrypted VEX)",
    )
    parser.add_argument("--content-encoding", choices=("json", "encrypted"))


def _add_encrypt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Validate cleartext --file, extract catalog metadata, encrypt with AES-256-GCM (SEVT v1), then push",
    )
    parser.add_argument(
        "--encrypt-openpgp",
        action="store_true",
        help="Fetch approved recipient keys from server, OpenPGP-encrypt locally, then push",
    )
    parser.add_argument(
        "--encryption-key-file",
        help="Path to 32-byte AES key (raw or base64 text) used when --encrypt is set",
    )
    parser.add_argument(
        "--encryption-key-id",
        help="Release label (OpenPGP) or subscriber key id (AES-256-GCM)",
    )
    parser.add_argument(
        "--pgp-private-key-file",
        help="Path to supplier PGP private key (armored); never uploaded to server",
    )
    parser.add_argument(
        "--pgp-passphrase-file",
        help="Optional file containing passphrase for protected private key",
    )
    parser.add_argument(
        "--encryption-recipients-scope",
        help="Optional scope query for GET /v1/supplier/me/encryption-recipients",
    )


def _add_validate_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        dest="validate_json",
        action="store_true",
        help="Print JSON result instead of human-readable report",
    )


def run_validate(args: argparse.Namespace) -> int:
    cfg = _load_config(args.config)
    vex_doc = _load_json(args.file)
    product_fields = _envelope_product_fields(cfg, args)
    try:
        vex_doc, product_fields = _prepare_vex_document(
            vex_doc,
            args=args,
            cfg=cfg,
            product_fields=product_fields,
        )
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1
    result = validate_vex_for_catalog(vex_doc, **product_fields)
    if args.validate_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_readiness_report(result))
    return 0 if result.ok else 1


def _require_catalog_readiness(
    vex_doc: dict[str, Any],
    product_fields: dict[str, Any],
) -> CatalogReadinessResult:
    result = validate_vex_for_catalog(vex_doc, **product_fields)
    if not result.ok:
        print(format_readiness_report(result), file=sys.stderr)
        raise SystemExit(1)
    if result.warnings:
        print(format_readiness_report(result), file=sys.stderr)
    return result


def run_push(args: argparse.Namespace) -> int:
    cfg = _load_config(args.config)
    base_url = cfg.get("base_url") or args.base_url
    supplier_slug = cfg.get("supplier_slug") or args.supplier_slug
    api_key = cfg.get("api_key") or args.api_key
    signing_pem = cfg.get("signing_key_pem") or args.signing_key_pem
    vex_doc = _load_json(args.file)
    product_fields = _envelope_product_fields(cfg, args)

    if not supplier_slug or not api_key:
        raise SystemExit("requires --supplier-slug and --api-key (or --config)")

    vex_doc, product_fields = _prepare_vex_document(
        vex_doc,
        args=args,
        cfg=cfg,
        product_fields=product_fields,
    )
    readiness = _require_catalog_readiness(vex_doc, product_fields)

    envelope = build_envelope(
        supplier_slug=supplier_slug,
        vex_document=vex_doc,
        product_name=product_fields.get("envelope_product_name") or readiness.product_name,
        product_version=product_fields.get("envelope_product_version") or readiness.product_version,
        product_purl=product_fields.get("envelope_purl") or readiness.product_purl,
        product_cpe=product_fields.get("envelope_cpe") or readiness.product_cpe,
        software_vendor_name=product_fields.get("envelope_software_vendor_name") or readiness.software_vendor_name,
        signing_key_pem_path=signing_pem,
        content_encoding=product_fields.get("content_encoding"),
    )
    resp = push_envelope(base_url, api_key, envelope, args.idem_key)
    print(resp.status_code)
    sys.stdout.write(resp.text)
    return 0 if resp.status_code < 400 else 1


def _build_validate_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Validate VEX catalog readiness without pushing to StreamingVEX",
    )
    _add_catalog_field_args(parser)
    _add_encrypt_args(parser)
    _add_validate_output_args(parser)
    return parser


def _build_push_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="StreamingVEX VEX Pusher — upload supplier-authenticated VEX envelopes",
    )
    _add_catalog_field_args(parser)
    _add_encrypt_args(parser)
    parser.add_argument("--base-url", default="https://streamingvex.example.com")
    parser.add_argument("--supplier-slug", help="Registered supplier slug")
    parser.add_argument("--api-key", help="Supplier API key from StreamingVEX")
    parser.add_argument("--signing-key-pem", help="Ed25519 private key PEM for envelope signature")
    parser.add_argument("--idem-key", help="Idempotency-Key header")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate only — do not push (same as the validate subcommand / streamingvex-validate)",
    )
    parser.add_argument(
        "--validate-json",
        action="store_true",
        help="With --validate, print JSON result instead of human-readable report",
    )
    return parser


def validate_main(argv: list[str] | None = None) -> None:
    parser = _build_validate_parser("streamingvex-validate")
    args = parser.parse_args(argv)
    raise SystemExit(run_validate(args))


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "validate":
        sub_argv = [a if a != "--validate-json" else "--json" for a in argv[1:]]
        parser = _build_validate_parser("streamingvex-push validate")
        args = parser.parse_args(sub_argv)
        raise SystemExit(run_validate(args))

    parser = _build_push_parser("streamingvex-push")
    args = parser.parse_args(argv)

    if args.validate:
        raise SystemExit(run_validate(args))

    raise SystemExit(run_push(args))


if __name__ == "__main__":
    main()
