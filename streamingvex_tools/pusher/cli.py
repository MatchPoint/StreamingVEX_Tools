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
from streamingvex_tools.pusher.validate import format_readiness_report, validate_vex_for_catalog


def _load_json(path: str | None) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    return json.loads(raw)


def _load_config(path: str | None) -> dict[str, Any]:
    return load_pusher_config(path) if path else {}


def build_envelope(
    *,
    supplier_slug: str,
    vex_document: dict[str, Any],
    product_name: str | None,
    product_version: str | None,
    product_purl: str | None,
    product_cpe: str | None,
    signing_key_pem_path: str | None,
    content_encoding: str | None = None,
) -> SupplierPushEnvelope:
    from streamingvex_tools.vex_encryption import is_encrypted_payload

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


def _envelope_product_fields(cfg: dict[str, Any], args: argparse.Namespace) -> dict[str, str | None]:
    return {
        "envelope_product_name": cfg.get("product_name") or args.product_name,
        "envelope_product_version": cfg.get("product_version") or args.product_version,
        "envelope_purl": cfg.get("product_purl") or args.product_purl,
        "envelope_cpe": cfg.get("product_cpe") or args.product_cpe,
        "content_encoding": cfg.get("content_encoding") or args.content_encoding,
    }


def _add_catalog_field_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="JSON config with optional product_name, product_version, product_purl, product_cpe")
    parser.add_argument("--file", help="VEX JSON file (OpenVEX/CSAF); stdin if omitted")
    parser.add_argument("--product-name")
    parser.add_argument("--product-version")
    parser.add_argument("--product-purl")
    parser.add_argument("--product-cpe")
    parser.add_argument("--content-encoding", choices=("json", "encrypted"))


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
    result = validate_vex_for_catalog(vex_doc, **_envelope_product_fields(cfg, args))
    if args.validate_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_readiness_report(result))
    return 0 if result.ok else 1


def _require_catalog_readiness(
    vex_doc: dict[str, Any],
    *,
    envelope_product_name: str | None,
    envelope_product_version: str | None,
    envelope_purl: str | None,
    envelope_cpe: str | None,
    content_encoding: str | None,
) -> None:
    result = validate_vex_for_catalog(
        vex_doc,
        envelope_product_name=envelope_product_name,
        envelope_product_version=envelope_product_version,
        envelope_purl=envelope_purl,
        envelope_cpe=envelope_cpe,
        content_encoding=content_encoding,
    )
    if not result.ok:
        print(format_readiness_report(result), file=sys.stderr)
        raise SystemExit(1)
    if result.warnings:
        print(format_readiness_report(result), file=sys.stderr)


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

    _require_catalog_readiness(vex_doc, **product_fields)

    envelope = build_envelope(
        supplier_slug=supplier_slug,
        vex_document=vex_doc,
        product_name=product_fields["envelope_product_name"],
        product_version=product_fields["envelope_product_version"],
        product_purl=product_fields["envelope_purl"],
        product_cpe=product_fields["envelope_cpe"],
        signing_key_pem_path=signing_pem,
        content_encoding=product_fields["content_encoding"],
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
    _add_validate_output_args(parser)
    return parser


def _build_push_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="StreamingVEX VEX Pusher — upload supplier-authenticated VEX envelopes",
    )
    _add_catalog_field_args(parser)
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
