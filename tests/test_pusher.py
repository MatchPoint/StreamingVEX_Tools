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


def test_example_config_is_valid_json() -> None:
    path = Path(__file__).resolve().parents[1] / "examples" / "pusher.config.example.json"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    assert "base_url" in cfg
    assert "supplier_slug" in cfg


def test_cli_help_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "streamingvex_tools.pusher.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "VEX Pusher" in result.stdout
