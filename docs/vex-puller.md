# VEX Pull subscriber (`streamingvex-pull`)

Outbound pull CLI for corporate PSIRT teams. Fetches subscribed catalog VEX over **HTTPS from inside your network** — no inbound firewall pinholes required.

Install from [StreamingVEX_tools](https://github.com/MatchPoint/StreamingVEX_tools):

```bash
pip install -e ".[dev]"
```

## Quick start

1. Create a personal API key at **`/ui/api-keys`** on your StreamingVEX server (`svx_u_…`).
2. Subscribe to catalog entries at **`/ui/catalog`**.
3. Copy [`examples/puller.config.example.json`](../examples/puller.config.example.json) to `puller.config.json`.
4. Run once (cron-friendly):

```bash
streamingvex-pull --config puller.config.json
```

Saved VEX files land under `output_dir` (default `./received_vex/{vendor}/{product}/{version}/`).

## Config reference

| Key | Required | Description |
|-----|----------|-------------|
| `base_url` | yes | StreamingVEX root URL |
| `api_key` | yes | Personal API key or JWT (`Authorization: Bearer`) |
| `output_dir` | no | Where to write JSON (default `./received_vex`) |
| `state_file` | no | Local dedupe state (default `.streamingvex-pull-state.json`) |
| `force_sync` | no | When `true`, `POST /catalog/{id}/force-sync` before fetch for public-pull sources |
| `proxy` | no | Corporate forward proxy URL (or set `HTTPS_PROXY`) |
| `poll_interval_minutes` | no | Used with `--daemon` for high-frequency pull |

JSON **comments** (`// …`) are supported (same loader as `pusher.config.json`).

## CLI flags

| Flag | Purpose |
|------|---------|
| `--config` | Path to `puller.config.json` |
| `--base-url` / `--api-key` | Override config |
| `--output-dir` | Override output directory |
| `--force-sync` | Trigger platform fetch before download |
| `--proxy` | HTTPS proxy override |
| `--daemon` | Loop using `poll_interval_minutes` |
| `--no-changes-api` | Poll all covered sources instead of `GET /subscriptions/changes` |

## How it works

1. **`GET /subscriptions/changes`** — lists catalog sources you subscribe to where the latest snapshot differs from your last server ack.
2. Optional **`POST /catalog/{id}/force-sync`** for public-pull sources when `force_sync` is enabled.
3. **`GET /catalog/{id}/latest-vex`** — download VEX JSON.
4. Compare **`content_sha256`** to local state; write file only when changed.
5. **`POST /subscriptions/ack`** — record successful pull on the server.

Fallback: **`GET /subscriptions/covered-catalog-sources`** when `--no-changes-api` is set.

## Corporate proxy

```bash
export HTTPS_PROXY=http://proxy.corp.example:8080
streamingvex-pull --config puller.config.json
```

Or set `"proxy"` in config.

## High-frequency pull (regulatory tier)

For sub-hour awareness (for example EU CRA Article 14 exploited-vulnerability workflows), run:

```bash
streamingvex-pull --config puller.config.json --daemon --poll-interval-minutes 15
```

Your worst-case detection delay is the poll interval unless you also use [webhooks](webhook-receiver.md).

## Cron example (Linux)

```cron
*/30 * * * * /opt/venv/bin/streamingvex-pull --config /etc/streamingvex/puller.config.json >> /var/log/streamingvex-pull.log 2>&1
```

## Encrypted VEX

When `content_encoding` is `encrypted`, the CLI saves the full API envelope (including ciphertext wrapper). Decrypt locally with your subscriber key — same as the webhook receiver.

## Related

- Server companion: [Enterprise delivery](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/enterprise-delivery.md) in StreamingVEX docs
- Push path (suppliers): [vex-pusher.md](vex-pusher.md)
- Inbound webhooks: [webhook-receiver.md](webhook-receiver.md)
