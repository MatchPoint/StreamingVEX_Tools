# StreamingVEX Tools

Public client tools for [StreamingVEX](https://github.com/MatchPoint/StreamingVEX) — the VEX aggregation broker. Use these without access to the private server implementation.

| Tool | Purpose |
|------|---------|
| **VEX Pull** (`streamingvex-pull`) | Subscribers pull subscribed VEX outbound (firewall-friendly) |
| **VEX Pusher** (`streamingvex-push`) | Suppliers publish VEX to `POST /v1/supplier/push` |
| **VEX Validate** (`streamingvex-validate`) | Check catalog readiness without pushing (no API key) |
| **Webhook receiver example** | Subscribers verify HMAC, dedupe, and store `catalog.vex.updated` events |

## Install

```bash
git clone https://github.com/MatchPoint/StreamingVEX_tools.git
cd StreamingVEX_tools
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
source .venv/bin/activate
pip install -e ".[dev,webhook]"
```

Commands on your PATH:

- `streamingvex-push` (alias `vex-pusher`)
- `streamingvex-validate` (validate-only)
- Example receiver: `python examples/webhook_receiver/receiver.py`

## Quick links

| Guide | Audience |
|-------|----------|
| [docs/vex-pusher.md](docs/vex-pusher.md) | Suppliers pushing VEX |
| [docs/webhook-receiver.md](docs/webhook-receiver.md) | Subscribers receiving webhooks |
| [docs/getting-started.md](docs/getting-started.md) | End-to-end local test |

## VEX Pusher (suppliers)

1. Get a StreamingVEX account and **verified email** (`/ui/register`).
2. Apply at **`/ui/supplier-pusher`** (supplier slug, company name, website); wait for admin approval.
3. Register supplier and API key at **`/ui/supplier`** (`svx_…`).
4. Validate, then push:

```bash
cp examples/pusher.config.example.json pusher.config.json
# Edit base_url, supplier_slug, api_key (product fields optional when VEX embeds metadata)

streamingvex-validate --file path/to/vex.csaf.json
streamingvex-push --config pusher.config.json --file path/to/vex.csaf.json --idem-key release-202602
```

**Canonical reference:** [docs/vex-pusher.md](docs/vex-pusher.md) — config fields, catalog readiness, plaintext vs encrypted (`--encrypt`), troubleshooting.

See [docs/getting-started.md](docs/getting-started.md) for a full local E2E with webhooks.

## Webhook receiver (subscribers)

1. Subscribe to catalog sources on your StreamingVEX server.
2. Add a webhook at **Webhooks** with URL and signing secret.
3. Run the example receiver:

```bash
export WEBHOOK_SECRET=your-secret-from-streamingvex
python examples/webhook_receiver/receiver.py --port 9000
```

Register `http://127.0.0.1:9000/webhook` (or your public URL) in StreamingVEX.

See [docs/webhook-receiver.md](docs/webhook-receiver.md) for event schema, HMAC verification, and production notes.

## Tests

```bash
pytest tests/ -v
```

## Repository layout

```
streamingvex_tools/     # Installable package (envelope, pusher CLI)
examples/
  webhook_receiver/     # Reference subscriber implementation
  pusher.config.example.json
docs/                   # User-facing guides
tests/
```

## License

MIT — see [LICENSE](LICENSE).
