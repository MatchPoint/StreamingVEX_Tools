"""HTTP client for StreamingVEX subscriber pull APIs."""

from __future__ import annotations

from typing import Any

import httpx


class PullClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        proxy: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        }
        proxy_url = proxy or None
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            proxy=proxy_url,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PullClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def get_covered_catalog_sources(self) -> list[dict[str, Any]]:
        resp = self._client.get(
            f"{self.base_url}/subscriptions/covered-catalog-sources",
            headers=self.headers,
        )
        resp.raise_for_status()
        body = resp.json()
        rows = body.get("sources") if isinstance(body, dict) else body
        return list(rows) if isinstance(rows, list) else []

    def get_subscription_changes(self, *, cursor: str | None = None) -> dict[str, Any]:
        params = {"cursor": cursor} if cursor else None
        resp = self._client.get(
            f"{self.base_url}/subscriptions/changes",
            headers=self.headers,
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    def ack_pull(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        resp = self._client.post(
            f"{self.base_url}/subscriptions/ack",
            headers={**self.headers, "Content-Type": "application/json"},
            json={"entries": entries},
        )
        resp.raise_for_status()
        return resp.json()

    def force_sync(self, catalog_source_id: int) -> dict[str, Any]:
        resp = self._client.post(
            f"{self.base_url}/catalog/{catalog_source_id}/force-sync",
            headers=self.headers,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_latest_vex(self, catalog_source_id: int) -> dict[str, Any]:
        resp = self._client.get(
            f"{self.base_url}/catalog/{catalog_source_id}/latest-vex",
            headers=self.headers,
        )
        resp.raise_for_status()
        return resp.json()
