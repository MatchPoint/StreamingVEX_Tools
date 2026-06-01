"""Tests for VEX encryption helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from streamingvex_tools.pusher.encrypt import encrypt_vex_document, load_aes256_key
from streamingvex_tools.pusher.validate import format_readiness_report, validate_vex_for_catalog
from streamingvex_tools.vex_encryption import parse_encrypted_payload


def test_load_aes256_key_raw_and_base64(tmp_path: Path) -> None:
    key = b"a" * 32
    raw_path = tmp_path / "raw.key"
    raw_path.write_bytes(key)
    assert load_aes256_key(raw_path) == key

    b64_path = tmp_path / "b64.key"
    b64_path.write_text(base64.b64encode(key).decode("ascii"), encoding="utf-8")
    assert load_aes256_key(b64_path) == key


def test_encrypt_vex_document_roundtrip(tmp_path: Path) -> None:
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    key_path = tmp_path / "vex.key"
    key_path.write_bytes(b"k" * 32)
    wrapper = encrypt_vex_document(
        fixture,
        key_path=key_path,
        key_id="demo-key",
        plaintext_format="openvex",
    )
    enc = parse_encrypted_payload(wrapper)
    assert enc.algorithm == "AES-256-GCM"
    assert enc.key_id == "demo-key"
    assert enc.plaintext_format == "openvex"
    assert enc.nonce is not None

    key = load_aes256_key(key_path)
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(enc.nonce),
        base64.b64decode(enc.ciphertext),
        None,
    )
    assert json.loads(plaintext.decode("utf-8")) == fixture


def test_encrypted_wrapper_without_metadata_shows_cli_help() -> None:
    wrapper = {
        "streamingvex_encrypted_vex": "1",
        "algorithm": "AES-256-GCM",
        "key_id": "demo-key",
        "ciphertext": "dGVzdA==",
        "nonce": "bm9uY2U=",
        "plaintext_format": "csaf",
    }
    result = validate_vex_for_catalog(
        wrapper,
        content_encoding="encrypted",
        require_software_vendor_name=True,
    )
    assert result.ok is False
    report = format_readiness_report(result)
    assert "--product-name" in report
    assert "--encrypt --encryption-key-file" in report


def test_encrypt_validate_flow(tmp_path: Path) -> None:
    from streamingvex_tools.pusher.cli import run_validate
    from argparse import Namespace

    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    vex_path = tmp_path / "sample.openvex.json"
    vex_path.write_text(json.dumps(fixture), encoding="utf-8")
    key_path = tmp_path / "vex.key"
    key_path.write_bytes(b"z" * 32)

    args = Namespace(
        config=None,
        file=str(vex_path),
        product_name=None,
        product_version=None,
        product_purl=None,
        product_cpe=None,
        software_vendor_name=None,
        content_encoding=None,
        encrypt=True,
        encryption_key_file=str(key_path),
        encryption_key_id="demo-key",
        validate_json=False,
    )
    assert run_validate(args) == 0
