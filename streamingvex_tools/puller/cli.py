#!/usr/bin/env python3
"""StreamingVEX pull subscriber — outbound fetch of subscribed catalog VEX."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from streamingvex_tools.puller.client import PullClient
from streamingvex_tools.puller.config_loader import load_puller_config
from streamingvex_tools.puller.state import get_saved_hash, load_state, mark_saved, save_state

_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._+-]+")


def _safe_segment(value: str | None, fallback: str) -> str:
    raw = (value or fallback).strip()
    cleaned = _SAFE_SEGMENT.sub("_", raw).strip("._")
    return cleaned or fallback


def _output_path(
    output_dir: Path,
    *,
    software_vendor: str | None,
    product_name: str | None,
    product_version: str | None,
    catalog_source_id: int,
    filename: str | None,
) -> Path:
    vendor = _safe_segment(software_vendor, "unknown-vendor")
    product = _safe_segment(product_name, f"catalog-{catalog_source_id}")
    version = _safe_segment(product_version, "unversioned")
    name = filename or f"{product}-{version}.json"
    if not name.endswith(".json"):
        name = f"{name}.json"
    return output_dir / vendor / product / version / name


def _resolve_proxy(cfg: dict[str, Any], args: argparse.Namespace) -> str | None:
    return cfg.get("proxy") or args.proxy or None


def _resolve_state_path(cfg: dict[str, Any], args: argparse.Namespace) -> Path:
    raw = cfg.get("state_file") or args.state_file or ".streamingvex-pull-state.json"
    return Path(raw)


def _write_vex_payload(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = payload.get("document")
    if payload.get("content_encoding") == "encrypted":
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    if isinstance(document, dict):
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pull_once(
    client: PullClient,
    *,
    output_dir: Path,
    state: dict[str, Any],
    force_sync: bool,
    use_changes_api: bool,
    cursor: str | None,
) -> tuple[int, str | None]:
    """Return (saved_count, new_cursor)."""

    saved = 0
    new_cursor = cursor
    ack_entries: list[dict[str, Any]] = []

    if use_changes_api:
        body = client.get_subscription_changes(cursor=cursor)
        sources = body.get("changes") or []
        new_cursor = body.get("cursor") or new_cursor
    else:
        sources = client.get_covered_catalog_sources()

    for src in sources:
        catalog_id = int(src["catalog_source_id"])
        discovery_model = src.get("discovery_model") or ""
        if force_sync and discovery_model == "public_pull":
            try:
                client.force_sync(catalog_id)
            except Exception as exc:  # noqa: BLE001
                print(f"force-sync skipped for {catalog_id}: {exc}", file=sys.stderr)

        try:
            payload = client.fetch_latest_vex(catalog_id)
        except Exception as exc:  # noqa: BLE001
            print(f"fetch failed for catalog {catalog_id}: {exc}", file=sys.stderr)
            continue

        content_sha256 = payload.get("content_sha256")
        if not content_sha256:
            print(f"no content_sha256 for catalog {catalog_id}; skipping", file=sys.stderr)
            continue

        if get_saved_hash(state, catalog_id) == content_sha256:
            continue

        out_path = _output_path(
            output_dir,
            software_vendor=payload.get("software_vendor_name") or src.get("software_vendor_name"),
            product_name=payload.get("product_name") or src.get("product_name"),
            product_version=payload.get("product_version") or src.get("product_version"),
            catalog_source_id=catalog_id,
            filename=payload.get("filename"),
        )
        _write_vex_payload(out_path, payload)
        mark_saved(
            state,
            catalog_source_id=catalog_id,
            content_sha256=str(content_sha256),
            snapshot_id=payload.get("snapshot_id"),
            path=str(out_path),
        )
        saved += 1
        print(f"saved catalog {catalog_id} -> {out_path}")
        ack_entries.append(
            {
                "catalog_source_id": catalog_id,
                "snapshot_id": payload.get("snapshot_id"),
                "content_sha256": content_sha256,
            }
        )

    if use_changes_api and ack_entries:
        try:
            client.ack_pull(ack_entries)
        except Exception as exc:  # noqa: BLE001
            print(f"ack failed (local state still updated): {exc}", file=sys.stderr)

    return saved, new_cursor


def run_pull(args: argparse.Namespace) -> int:
    cfg: dict[str, Any] = {}
    if args.config:
        try:
            cfg = load_puller_config(args.config)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    base_url = cfg.get("base_url") or args.base_url
    api_key = cfg.get("api_key") or args.api_key
    if not base_url or not api_key:
        print("requires base_url and api_key (--config or flags)", file=sys.stderr)
        return 1

    output_dir = Path(cfg.get("output_dir") or args.output_dir or "./received_vex")
    state_path = _resolve_state_path(cfg, args)
    state = load_state(state_path)
    force_sync = bool(cfg.get("force_sync", False) or args.force_sync)
    use_changes_api = not args.no_changes_api
    poll_minutes = cfg.get("poll_interval_minutes") or args.poll_interval_minutes
    proxy = _resolve_proxy(cfg, args)
    cursor = state.get("changes_cursor")

    with PullClient(base_url, api_key, proxy=proxy) as client:
        if args.daemon and poll_minutes:
            interval = max(1, int(poll_minutes)) * 60
            print(f"pull daemon: every {poll_minutes} minute(s); output {output_dir}", file=sys.stderr)
            while True:
                saved, cursor = pull_once(
                    client,
                    output_dir=output_dir,
                    state=state,
                    force_sync=force_sync,
                    use_changes_api=use_changes_api,
                    cursor=cursor if use_changes_api else None,
                )
                if cursor:
                    state["changes_cursor"] = cursor
                save_state(state_path, state)
                if saved:
                    print(f"pulled {saved} update(s)", file=sys.stderr)
                time.sleep(interval)

        saved, cursor = pull_once(
            client,
            output_dir=output_dir,
            state=state,
            force_sync=force_sync,
            use_changes_api=use_changes_api,
            cursor=cursor if use_changes_api else None,
        )
        if cursor:
            state["changes_cursor"] = cursor
        save_state(state_path, state)
        print(f"done: {saved} new or updated document(s)")
        return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="streamingvex-pull",
        description="Pull subscribed VEX from StreamingVEX (outbound HTTPS, firewall-friendly)",
    )
    parser.add_argument("--config", help="puller.config.json path")
    parser.add_argument("--base-url", help="StreamingVEX base URL")
    parser.add_argument("--api-key", help="Personal API key (svx_u_…) or JWT")
    parser.add_argument(
        "--output-dir",
        default="./received_vex",
        help="Directory tree for saved VEX JSON",
    )
    parser.add_argument(
        "--state-file",
        help="Local dedupe state file (default .streamingvex-pull-state.json)",
    )
    parser.add_argument(
        "--force-sync",
        action="store_true",
        help="POST force-sync for public_pull sources before fetch",
    )
    parser.add_argument(
        "--proxy",
        help="HTTPS proxy URL (or set HTTPS_PROXY); overrides config proxy",
    )
    parser.add_argument(
        "--poll-interval-minutes",
        type=int,
        help="When --daemon, minutes between pull cycles (CRA/high-frequency tier)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously using poll_interval_minutes from config or flag",
    )
    parser.add_argument(
        "--no-changes-api",
        action="store_true",
        help="Poll every covered catalog source instead of GET /subscriptions/changes",
    )
    args = parser.parse_args(argv)
    raise SystemExit(run_pull(args))


if __name__ == "__main__":
    main()
