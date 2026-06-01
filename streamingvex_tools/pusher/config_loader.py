"""Load pusher.config.json with // line comments (JSONC-style)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def strip_json_line_comments(text: str) -> str:
    """Remove // comments outside JSON string literals."""

    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def load_pusher_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    raw = config_path.read_text(encoding="utf-8")
    stripped = strip_json_line_comments(raw)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid pusher.config.json ({config_path}) at line {exc.lineno}, column {exc.colno}: {exc.msg}. "
            "If you uncommented an optional field, add a comma after the previous property "
            "(see the example comment above the OPTIONAL block)."
        ) from exc
