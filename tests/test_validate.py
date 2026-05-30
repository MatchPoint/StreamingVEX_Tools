"""Tests for catalog readiness validation in streamingvex_tools."""

from __future__ import annotations

import json
import subprocess
import sys
from io import StringIO
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from streamingvex_tools.pusher.validate import format_readiness_report, validate_vex_for_catalog


def test_openvex_fixture_passes() -> None:
    payload = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    result = validate_vex_for_catalog(payload)
    assert result.ok is True
    assert result.format_name == "openvex"
    assert result.product_name == "acme-fw-mgr"


def test_unknown_format_fails() -> None:
    result = validate_vex_for_catalog({"foo": "bar"})
    assert result.ok is False
    assert any("unrecognized VEX format" in err for err in result.errors)


def test_validate_main_direct(tmp_path: Path) -> None:
    from streamingvex_tools.pusher.cli import validate_main

    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    vex_path = tmp_path / "sample.openvex.json"
    vex_path.write_text(json.dumps(fixture), encoding="utf-8")

    buf = StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit) as exc:
        validate_main(["--file", str(vex_path)])
    assert exc.value.code == 0
    assert "Catalog readiness: OK" in buf.getvalue()


def test_cli_validate_subcommand(tmp_path: Path) -> None:
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.openvex.json").read_text(
            encoding="utf-8"
        )
    )
    vex_path = tmp_path / "sample.openvex.json"
    vex_path.write_text(json.dumps(fixture), encoding="utf-8")

    for cmd in (
        [sys.executable, "-m", "streamingvex_tools.pusher.cli", "--validate", "--file", str(vex_path)],
        [sys.executable, "-m", "streamingvex_tools.pusher.cli", "validate", "--file", str(vex_path)],
    ):
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 0, result.stderr or result.stdout
        assert "Catalog readiness: OK" in result.stdout


def test_push_blocks_invalid_vex_locally(tmp_path: Path) -> None:
    vex_path = tmp_path / "bad.json"
    vex_path.write_text('{"not": "vex"}', encoding="utf-8")
    config_path = tmp_path / "pusher.config.json"
    config_path.write_text(
        json.dumps(
            {
                "base_url": "http://127.0.0.1:1",
                "supplier_slug": "test-supplier",
                "api_key": "svx_test",
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "streamingvex_tools.pusher.cli",
            "--config",
            str(config_path),
            "--file",
            str(vex_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1
    assert "Catalog readiness: FAILED" in result.stderr


def test_format_readiness_report() -> None:
    result = validate_vex_for_catalog({"foo": "bar"})
    text = format_readiness_report(result)
    assert "FAILED" in text
