# Webhook receiver example

Reference implementation for subscribers receiving **`catalog.vex.updated`** events from StreamingVEX.

Source: [`examples/webhook_receiver/`](../examples/webhook_receiver/)

## What every subscriber should implement

| Concern | Pattern in example |
|---------|-------------------|
| Authenticity | HMAC-SHA256 over **raw** POST body: header `X-Streamingvex-Signature: sha256=<hex>` |
| Idempotency | Dedupe on `snapshot_id` + `content_sha256` |
| Persistence | Store full JSON event (includes `document` VEX payload) |
| Encrypted VEX | Store ciphertext; decrypt locally using `encryption.key_id` |

## Install and run

```bash
pip install "streamingvex-tools[webhook]"
export WEBHOOK_SECRET=your-signing-secret-from-streamingvex
python examples/webhook_receiver/receiver.py --port 9000
```

Register in StreamingVEX **Webhooks** (`/ui/webhooks`):

| Field | Example |
|-------|---------|
| URL | `http://127.0.0.1:9000/webhook` |
| Signing secret | Same as `WEBHOOK_SECRET` |

Health check: `GET http://127.0.0.1:9000/health`

## Event shape

```json
{
  "event": "catalog.vex.updated",
  "catalog_source_id": 7,
  "snapshot_id": 99,
  "content_sha256": "abc123...",
  "content_encoding": "json",
  "force_sync": false,
  "document": { }
}
```

When `content_encoding` is `encrypted`, `document` holds the ciphertext wrapper and `encryption` metadata is included.

## HMAC verification

```python
import hashlib
import hmac

def verify(body: bytes, secret: str, header: str) -> bool:
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header[7:], expected)
```

Must use the **exact** bytes received in the HTTP body (before JSON re-serialization).

## Idempotency

```python
key = f"{event['snapshot_id']}:{event['content_sha256']}"
```

Persist seen keys across restarts (see `SeenEventStore` in `verify.py`).

## Production checklist

- Terminate TLS at your edge; use HTTPS webhook URLs in production.
- Return **2xx** quickly; process asynchronously if needed.
- Reject unsigned requests when a secret is configured.
- Log `catalog_source_id`, `snapshot_id`, and delivery outcome.
- For encrypted VEX, never log decryption keys.

## Integrate into your stack

Copy `verify.py` into your service, or reimplement the three functions:

- `verify_streamingvex_signature`
- `parse_catalog_event`
- `idempotency_key` + durable dedupe store

Framework examples: FastAPI (included), Flask, ASP.NET, Go `http.Handler` with `hmac.Equal`.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `401 invalid signature` | Secret matches StreamingVEX webhook config; verify raw body |
| No deliveries | Subscription active? Webhook URL reachable? Force sync on catalog source |
| Duplicate files | Expected on retries — dedupe should return `duplicate` without re-processing |
