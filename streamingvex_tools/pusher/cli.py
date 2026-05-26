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


def _load_json(path: str | None) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    return json.loads(raw)


def _load_config(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="StreamingVEX VEX Pusher — upload supplier-authenticated VEX envelopes",
    )
    parser.add_argument("--config", help="JSON config: base_url, supplier_slug, api_key, signing_key_pem")
    parser.add_argument("--base-url", default="https://streamingvex.example.com")
    parser.add_argument("--supplier-slug", help="Registered supplier slug")
    parser.add_argument("--api-key", help="Supplier API key from StreamingVEX")
    parser.add_argument("--file", help="VEX JSON file (OpenVEX/CSAF); stdin if omitted")
    parser.add_argument("--product-name")
    parser.add_argument("--product-version")
    parser.add_argument("--product-purl")
    parser.add_argument("--product-cpe")
    parser.add_argument("--signing-key-pem", help="Ed25519 private key PEM for envelope signature")
    parser.add_argument("--content-encoding", choices=("json", "encrypted"))
    parser.add_argument("--idem-key", help="Idempotency-Key header")
    args = parser.parse_args()

    cfg: dict[str, Any] = {}
    if args.config:
        cfg = _load_config(args.config)

    base_url = cfg.get("base_url") or args.base_url
    supplier_slug = cfg.get("supplier_slug") or args.supplier_slug
    api_key = cfg.get("api_key") or args.api_key
    signing_pem = cfg.get("signing_key_pem") or args.signing_key_pem

    vex_doc = _load_json(args.file)

    if not supplier_slug or not api_key:
        parser.error("requires --supplier-slug and --api-key (or --config)")

    envelope = build_envelope(
        supplier_slug=supplier_slug,
        vex_document=vex_doc,
        product_name=cfg.get("product_name") or args.product_name,
        product_version=cfg.get("product_version") or args.product_version,
        product_purl=cfg.get("product_purl") or args.product_purl,
        product_cpe=cfg.get("product_cpe") or args.product_cpe,
        signing_key_pem_path=signing_pem,
        content_encoding=cfg.get("content_encoding") or args.content_encoding,
    )
    resp = push_envelope(base_url, api_key, envelope, args.idem_key)
    print(resp.status_code)
    sys.stdout.write(resp.text)
    if resp.status_code >= 400:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
