"""HMAC verification and idempotency helpers for StreamingVEX webhook events."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


def verify_streamingvex_signature(body: bytes, secret: str | None, signature_header: str | None) -> bool:
    if not secret:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    supplied = signature_header[7:]
    expected = hmac.new(secret.encode("utf-8"), body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def parse_catalog_event(body: bytes) -> dict[str, Any]:
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("event must be a JSON object")
    return payload


def idempotency_key(event: dict[str, Any]) -> str | None:
    snapshot_id = event.get("snapshot_id")
    content_sha256 = event.get("content_sha256")
    if snapshot_id is None or not content_sha256:
        return None
    return f"{snapshot_id}:{content_sha256}"


class SeenEventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._seen: set[str] = set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._seen.add(line)

    def already_processed(self, key: str) -> bool:
        return key in self._seen

    def mark_processed(self, key: str) -> None:
        if key in self._seen:
            return
        self._seen.add(key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(key + "\n")
