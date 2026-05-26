#!/usr/bin/env python3
"""
Example webhook receiver for StreamingVEX catalog VEX delivery.

    pip install "streamingvex-tools[webhook]"
    export WEBHOOK_SECRET=your-signing-secret
    python examples/webhook_receiver/receiver.py --port 9000
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

_EXAMPLE_DIR = Path(__file__).resolve().parent
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

from verify import SeenEventStore, idempotency_key, parse_catalog_event, verify_streamingvex_signature

logger = logging.getLogger("streamingvex.webhook_receiver")

app = FastAPI(
    title="StreamingVEX example webhook receiver",
    description="Receives catalog.vex.updated events and stores VEX documents locally.",
    version="0.1.0",
)

_webhook_secret: str | None = os.environ.get("WEBHOOK_SECRET")
_storage_dir = Path(os.environ.get("WEBHOOK_STORAGE_DIR", "./data/received_vex"))
_seen_store = SeenEventStore(_storage_dir / ".seen_events")


def _configure(*, secret: str | None, storage_dir: Path, seen_file: Path) -> None:
    global _webhook_secret, _storage_dir, _seen_store
    _webhook_secret = secret
    _storage_dir = storage_dir
    _seen_store = SeenEventStore(seen_file)


def _save_document(event: dict[str, Any]) -> Path:
    catalog_id = event.get("catalog_source_id", "unknown")
    snapshot_id = event.get("snapshot_id", "unknown")
    dest_dir = _storage_dir / str(catalog_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_path = dest_dir / f"snapshot-{snapshot_id}.json"
    out_path.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook")
async def receive_vex_webhook(
    request: Request,
    x_streamingvex_signature: str | None = Header(default=None, alias="X-Streamingvex-Signature"),
    x_streamingvex_event: str | None = Header(default=None, alias="X-Streamingvex-Event"),
) -> JSONResponse:
    body = await request.body()
    if not verify_streamingvex_signature(body, _webhook_secret, x_streamingvex_signature):
        raise HTTPException(status_code=401, detail="invalid signature")

    try:
        event = parse_catalog_event(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid event JSON: {exc}") from exc

    event_name = event.get("event") or x_streamingvex_event
    if event_name != "catalog.vex.updated":
        logger.warning("unexpected event type: %s", event_name)

    dedupe = idempotency_key(event)
    if dedupe and _seen_store.already_processed(dedupe):
        logger.info("duplicate delivery ignored: %s", dedupe)
        return JSONResponse({"status": "duplicate", "idempotency_key": dedupe})

    if event.get("content_encoding") == "encrypted":
        logger.info(
            "encrypted VEX received (key_id=%s); store ciphertext and decrypt locally",
            (event.get("encryption") or {}).get("key_id"),
        )

    saved_path = _save_document(event)
    if dedupe:
        _seen_store.mark_processed(dedupe)

    return JSONResponse(
        {
            "status": "accepted",
            "event": event_name,
            "catalog_source_id": event.get("catalog_source_id"),
            "snapshot_id": event.get("snapshot_id"),
            "content_sha256": event.get("content_sha256"),
            "saved_to": str(saved_path),
            "received_at": datetime.now(UTC).isoformat(),
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="StreamingVEX example webhook receiver")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret", default=os.environ.get("WEBHOOK_SECRET"))
    parser.add_argument("--storage-dir", default=os.environ.get("WEBHOOK_STORAGE_DIR", "./data/received_vex"))
    parser.add_argument("--seen-file", default=os.environ.get("WEBHOOK_SEEN_FILE", "./data/received_vex/.seen_events"))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _configure(secret=args.secret, storage_dir=Path(args.storage_dir), seen_file=Path(args.seen_file))

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
