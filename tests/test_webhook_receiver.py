"""Tests for the example webhook receiver."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "webhook_receiver"


def _load_module(name: str, filename: str):
    if str(_EXAMPLE_DIR) not in sys.path:
        sys.path.insert(0, str(_EXAMPLE_DIR))
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE_DIR / filename)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


verify = _load_module("webhook_verify", "verify.py")
receiver = _load_module("webhook_receiver", "receiver.py")


def _sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, digestmod=hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _catalog_event(**overrides) -> dict:
    base = {
        "event": "catalog.vex.updated",
        "catalog_source_id": 7,
        "snapshot_id": 99,
        "content_sha256": "abc123deadbeef",
        "content_encoding": "json",
        "document": {"document": {"title": "test-vex"}},
    }
    base.update(overrides)
    return base


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    receiver._configure(secret="test-secret", storage_dir=tmp_path / "vex", seen_file=tmp_path / "seen")
    return TestClient(receiver.app)


def test_verify_signature() -> None:
    body = b'{"event":"catalog.vex.updated"}'
    assert verify.verify_streamingvex_signature(body, "s3cr3t", _sign(body, "s3cr3t"))
    assert not verify.verify_streamingvex_signature(body, "s3cr3t", None)


def test_webhook_accepts_and_deduplicates(client: TestClient, tmp_path: Path) -> None:
    event = _catalog_event()
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    headers = {"X-Streamingvex-Signature": _sign(body, "test-secret")}

    assert client.post("/webhook", content=body, headers=headers).json()["status"] == "accepted"
    assert client.post("/webhook", content=body, headers=headers).json()["status"] == "duplicate"
    assert (tmp_path / "vex" / "7" / "snapshot-99.json").exists()


def test_webhook_rejects_bad_signature(client: TestClient) -> None:
    body = b'{"event":"catalog.vex.updated"}'
    assert client.post("/webhook", content=body, headers={"X-Streamingvex-Signature": "sha256=bad"}).status_code == 401
