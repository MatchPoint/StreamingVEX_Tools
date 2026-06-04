"""Fetch approved encryption recipients from StreamingVEX."""

from __future__ import annotations

from typing import Any

import httpx


def fetch_encryption_recipients(
    *,
    base_url: str,
    api_key: str,
    scope: str | None = None,
    timeout: float = 60.0,
) -> list[dict[str, Any]]:
    url = base_url.rstrip("/") + "/v1/supplier/me/encryption-recipients"
    params = {"scope": scope} if scope else None
    headers = {"X-Supplier-API-Key": api_key}
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers, params=params)
    if resp.status_code >= 400:
        raise RuntimeError(f"encryption-recipients failed ({resp.status_code}): {resp.text}")
    body = resp.json()
    if not isinstance(body, list):
        raise RuntimeError("unexpected encryption-recipients response")
    if not body:
        raise RuntimeError(
            "no approved encryption recipients — consumers must request access and you must approve"
        )
    return body
