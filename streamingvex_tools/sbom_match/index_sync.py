"""Download and cache catalog match index."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx


def sync_match_index(*, base_url: str, out_path: Path, api_key: str | None = None) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    url = f"{base_url.rstrip('/')}/catalog/match-index"
    with httpx.Client(timeout=60.0) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def load_match_index(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("entries") or [])
