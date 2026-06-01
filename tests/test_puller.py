"""Tests for streamingvex-pull CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from streamingvex_tools.puller.cli import pull_once, run_pull
from streamingvex_tools.puller.state import load_state, save_state


def test_pull_once_skips_unchanged_hash(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    output_dir = tmp_path / "out"
    state = load_state(state_path)
    mark_args = {
        "catalog_source_id": 1,
        "content_sha256": "abc123",
        "snapshot_id": 10,
        "path": str(output_dir / "x.json"),
    }
    from streamingvex_tools.puller.state import mark_saved

    mark_saved(state, **mark_args)
    save_state(state_path, state)

    client = MagicMock()
    client.get_covered_catalog_sources.return_value = [
        {
            "catalog_source_id": 1,
            "product_name": "EDK II",
            "software_vendor_name": "TianoCore",
            "product_version": "202411",
            "discovery_model": "registered_supplier_push",
        }
    ]
    client.fetch_latest_vex.return_value = {
        "catalog_source_id": 1,
        "content_sha256": "abc123",
        "product_name": "EDK II",
        "product_version": "202411",
        "software_vendor_name": "TianoCore",
        "filename": "edk.json",
        "document": {"statements": []},
    }

    saved, _ = pull_once(
        client,
        output_dir=output_dir,
        state=state,
        force_sync=False,
        use_changes_api=False,
        cursor=None,
    )
    assert saved == 0
    client.fetch_latest_vex.assert_called_once()


def test_pull_once_writes_new_document(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    state: dict = {"sources": {}}
    client = MagicMock()
    client.get_subscription_changes.return_value = {
        "changes": [
            {
                "catalog_source_id": 5,
                "product_name": "fw",
                "software_vendor_name": "Acme",
                "product_version": "1.0",
                "discovery_model": "public_pull",
            }
        ],
        "cursor": "cursor-token",
    }
    client.fetch_latest_vex.return_value = {
        "catalog_source_id": 5,
        "snapshot_id": 99,
        "content_sha256": "deadbeef",
        "product_name": "fw",
        "product_version": "1.0",
        "software_vendor_name": "Acme",
        "filename": "fw.json",
        "document": {"vulnerabilities": []},
    }

    saved, cursor = pull_once(
        client,
        output_dir=output_dir,
        state=state,
        force_sync=True,
        use_changes_api=True,
        cursor=None,
    )
    assert saved == 1
    assert cursor == "cursor-token"
    client.force_sync.assert_called_once_with(5)
    client.ack_pull.assert_called_once()
    files = list(output_dir.rglob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text(encoding="utf-8")) == {"vulnerabilities": []}


def test_run_pull_requires_config(tmp_path: Path) -> None:
    cfg = tmp_path / "puller.config.json"
    cfg.write_text(
        json.dumps({"base_url": "http://127.0.0.1:8000", "api_key": "svx_u_test"}),
        encoding="utf-8",
    )
    with patch("streamingvex_tools.puller.cli.PullClient") as client_cls:
        instance = client_cls.return_value.__enter__.return_value
        instance.get_subscription_changes.return_value = {"changes": [], "cursor": None}
        code = run_pull(
            type(
                "Args",
                (),
                {
                    "config": str(cfg),
                    "base_url": None,
                    "api_key": None,
                    "output_dir": str(tmp_path / "out"),
                    "state_file": None,
                    "force_sync": False,
                    "proxy": None,
                    "poll_interval_minutes": None,
                    "daemon": False,
                    "no_changes_api": False,
                },
            )()
        )
    assert code == 0
