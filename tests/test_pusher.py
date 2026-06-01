"""Tests for streamingvex_tools pusher CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from streamingvex_tools.envelope import SupplierPushEnvelope, verify_envelope_signature
from streamingvex_tools.pusher.cli import build_envelope, push_envelope


@pytest.fixture()
def signing_key_pem(tmp_path: Path) -> Path:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path = tmp_path / "supplier-private.pem"
    path.write_bytes(pem)
    pub_pem = (
        priv.public_key()
        .public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    (tmp_path / "supplier-public.pem").write_text(pub_pem, encoding="utf-8")
    return path


def test_build_envelope_with_signing(signing_key_pem: Path) -> None:
    env = build_envelope(
        supplier_slug="test-supplier",
        vex_document={"statements": []},
        product_name="EDK II",
        product_version="1.0",
        product_purl=None,
        product_cpe=None,
        software_vendor_name=None,
        signing_key_pem_path=str(signing_key_pem),
    )
    assert env.signature is not None
    pub = (signing_key_pem.parent / "supplier-public.pem").read_text(encoding="utf-8")
    assert verify_envelope_signature(env, pub)


def test_push_envelope_posts_to_supplier_api() -> None:
    env = SupplierPushEnvelope(supplier_slug="sup", vex_document={"statements": []}, product_name="p")
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("streamingvex_tools.pusher.cli.httpx.Client") as client_cls:
        client = MagicMock()
        client_cls.return_value.__enter__.return_value = client
        client.post.return_value = mock_resp
        push_envelope("http://127.0.0.1:8000", "svx_test", env, "idem-1")

    call = client.post.call_args
    assert call[0][0] == "http://127.0.0.1:8000/v1/supplier/push"
    assert call[1]["headers"]["X-Supplier-API-Key"] == "svx_test"


def test_example_config_loads_with_comments() -> None:
    from streamingvex_tools.pusher.config_loader import load_pusher_config

    path = Path(__file__).resolve().parents[1] / "examples" / "pusher.config.example.json"
    cfg = load_pusher_config(path)
    assert "base_url" in cfg
    assert "supplier_slug" in cfg
    assert "api_key" in cfg
    assert "product_name" not in cfg
    assert "product_version" not in cfg


def test_load_config_strips_line_comments(tmp_path: Path) -> None:
    from streamingvex_tools.pusher.config_loader import load_pusher_config

    path = tmp_path / "pusher.config.json"
    path.write_text(
        """{
  // comment
  "base_url": "http://127.0.0.1:8000",
  "supplier_slug": "test",
  "api_key": "svx_x",
  "product_name": "p",
  "product_version": "1"
}""",
        encoding="utf-8",
    )
    cfg = load_pusher_config(path)
    assert cfg["base_url"] == "http://127.0.0.1:8000"


def test_load_config_reports_missing_comma(tmp_path: Path) -> None:
    from streamingvex_tools.pusher.config_loader import load_pusher_config

    path = tmp_path / "pusher.config.json"
    path.write_text(
        """{
  "base_url": "http://127.0.0.1:8000",
  "supplier_slug": "test",
  "api_key": "svx_x",
  "product_name": "p",
  "product_version": "1.0.0"
  "product_cpe": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"
}""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="add a comma"):
        load_pusher_config(path)


def test_cli_help_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "streamingvex_tools.pusher.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "VEX Pusher" in result.stdout
    assert "--validate" in result.stdout


def test_validate_openvex_fixture() -> None:
    from streamingvex_tools.pusher.validate import validate_vex_for_catalog

    payload = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    result = validate_vex_for_catalog(payload)
    assert result.ok is True
    assert result.product_name == "acme-fw-mgr"
