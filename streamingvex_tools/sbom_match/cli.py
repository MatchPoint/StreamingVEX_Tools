#!/usr/bin/env python3
"""Client-side SBOM-to-catalog matching (NDA-safe — SBOM stays local)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx

from streamingvex_tools.sbom_match.index_sync import load_match_index, sync_match_index
from streamingvex_tools.sbom_match.outreach_draft import draft_supplier_outreach_email
from streamingvex_tools.sbom_match.report import build_sbom_match_report


def _load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def cmd_sync_index(args: argparse.Namespace) -> int:
    cfg = _load_config(Path(args.config)) if args.config else {}
    base_url = args.base_url or cfg.get("base_url") or "http://127.0.0.1:8000"
    out = Path(args.out or cfg.get("catalog_index_file") or "catalog-match-index.json")
    api_key = args.api_key or cfg.get("api_key")
    payload = sync_match_index(base_url=base_url, out_path=out, api_key=api_key)
    print(f"Wrote {out} ({payload.get('entry_count', 0)} entries, etag={payload.get('etag', '')[:12]}…)")
    return 0


def cmd_match(args: argparse.Namespace) -> int:
    sbom_path = Path(args.sbom)
    index_path = Path(args.index)
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    index = load_match_index(index_path)
    report = build_sbom_match_report(sbom, index)
    out = Path(args.out) if args.out else sbom_path.with_suffix(".match-report.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {report['matched_count']} match(es), {report['gap_count']} gap(s) -> {out}")
    if report.get("primary_component"):
        pc = report["primary_component"]
        print(f"Primary: {pc.get('name')} {pc.get('version') or ''}")
    return 0


def cmd_subscribe(args: argparse.Namespace) -> int:
    cfg = _load_config(Path(args.config))
    base_url = cfg.get("base_url") or "http://127.0.0.1:8000"
    api_key = cfg.get("api_key")
    if not api_key:
        print("api_key required in config", file=sys.stderr)
        return 1
    report_path = Path(args.report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    ids = args.catalog_source_ids
    if not ids:
        ids = [m["recommended_catalog_source_id"] for m in report.get("matches", [])]
    url = f"{base_url.rstrip('/')}/subscriptions/subscribe-catalog-sources"
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"catalog_source_ids": ids, "source": "sbom_match_cli"},
        )
        resp.raise_for_status()
        data = resp.json()
    print(f"Subscribed: {data.get('subscribed_catalog_source_ids')}")
    if data.get("errors"):
        print("Errors:", data["errors"], file=sys.stderr)
    return 0


def cmd_fetch_vex(args: argparse.Namespace) -> int:
    cfg = _load_config(Path(args.config))
    base_url = cfg.get("base_url") or "http://127.0.0.1:8000"
    api_key = cfg.get("api_key")
    if not api_key:
        print("api_key required in config", file=sys.stderr)
        return 1
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    headers = {"Authorization": f"Bearer {api_key}"}
    with httpx.Client(timeout=60.0) as client:
        for m in report.get("matches", []):
            cid = m["recommended_catalog_source_id"]
            resp = client.get(f"{base_url.rstrip('/')}/catalog/{cid}/latest-vex", headers=headers)
            if resp.status_code == 403:
                print(f"Skip {cid}: subscribe first", file=sys.stderr)
                continue
            resp.raise_for_status()
            payload = resp.json()
            name = payload.get("filename") or f"catalog-{cid}.json"
            path = out_dir / name
            doc = payload.get("document") or payload
            path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {path}")
    return 0


def cmd_outreach_draft(args: argparse.Namespace) -> int:
    draft = draft_supplier_outreach_email(
        downstream_org_name=args.downstream_org,
        downstream_product_name=args.downstream_product,
        downstream_product_version=args.downstream_version,
        target_supplier_name=args.target_supplier,
        target_product_name=args.target_product,
        target_product_version=args.target_version,
        base_url=args.base_url,
    )
    if args.out:
        Path(args.out).write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8")
    else:
        print("Subject:", draft["subject"])
        print(draft["body"])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Match SBOM against StreamingVEX catalog locally")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser("sync-index", help="Download catalog match index")
    p_sync.add_argument("--config", help="JSON config with base_url, api_key (optional)")
    p_sync.add_argument("--base-url")
    p_sync.add_argument("--out", help="Output JSON path")
    p_sync.add_argument("--api-key")
    p_sync.set_defaults(func=cmd_sync_index)

    p_match = sub.add_parser("match", help="Match local SBOM against cached index")
    p_match.add_argument("--sbom", required=True)
    p_match.add_argument("--index", required=True)
    p_match.add_argument("--out")
    p_match.set_defaults(func=cmd_match)

    p_sub = sub.add_parser("subscribe", help="Subscribe to catalog_source_ids from report")
    p_sub.add_argument("--config", required=True)
    p_sub.add_argument("--report", required=True)
    p_sub.add_argument("catalog_source_ids", nargs="*", type=int)
    p_sub.set_defaults(func=cmd_subscribe)

    p_vex = sub.add_parser("fetch-vex", help="Download VEX for matched catalog sources")
    p_vex.add_argument("--config", required=True)
    p_vex.add_argument("--report", required=True)
    p_vex.add_argument("--out-dir", required=True)
    p_vex.set_defaults(func=cmd_fetch_vex)

    p_out = sub.add_parser("outreach-draft", help="Draft supplier outreach email locally")
    p_out.add_argument("--downstream-org", required=True)
    p_out.add_argument("--downstream-product", required=True)
    p_out.add_argument("--downstream-version", default=None)
    p_out.add_argument("--target-supplier", required=True)
    p_out.add_argument("--target-product", required=True)
    p_out.add_argument("--target-version", default=None)
    p_out.add_argument("--base-url", default="https://streamingvex.org")
    p_out.add_argument("--out")
    p_out.set_defaults(func=cmd_outreach_draft)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
