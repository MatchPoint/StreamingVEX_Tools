"""Local pull state — tracks last saved content_sha256 per catalog source."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"sources": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"sources": {}}
    if not isinstance(data, dict):
        return {"sources": {}}
    data.setdefault("sources", {})
    return data


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_saved_hash(state: dict[str, Any], catalog_source_id: int) -> str | None:
    entry = state.get("sources", {}).get(str(catalog_source_id))
    if isinstance(entry, dict):
        value = entry.get("content_sha256")
        return str(value) if value else None
    return None


def mark_saved(
    state: dict[str, Any],
    *,
    catalog_source_id: int,
    content_sha256: str,
    snapshot_id: int | None,
    path: str,
) -> None:
    state.setdefault("sources", {})[str(catalog_source_id)] = {
        "content_sha256": content_sha256,
        "snapshot_id": snapshot_id,
        "path": path,
    }
