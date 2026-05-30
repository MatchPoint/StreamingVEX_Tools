# Getting started

This guide walks through a **local** supplier push and subscriber webhook using StreamingVEX Tools against your StreamingVEX server (hosted privately or on your network).

## Prerequisites

- Python **3.11+**
- A running StreamingVEX server URL (example: `http://127.0.0.1:8000`)
- Two roles: one **supplier** account (approved pusher) and one **subscriber** account

Install tools:

```bash
pip install -e ".[dev,webhook]"
```

## Part 1 — Supplier pushes VEX

### Account and approval

1. Register and verify email on the StreamingVEX web UI (`/ui/register`).
2. Apply at **`/ui/supplier-pusher`** — enter supplier slug, company name, and supplier website.
3. Platform admin (`PLATFORM_ADMIN_EMAILS`) reviews at **`/ui/admin/supplier-pushers`** and approves or denies (you receive an email).
4. Register supplier and API key at **`/ui/supplier`** (or REST: `POST /suppliers/register`, `POST /suppliers/{id}/credentials`) — save the `api_key`.

Details: [vex-pusher.md](vex-pusher.md).

### Validate then push

```bash
cp examples/pusher.config.example.json pusher.config.json
# Set base_url, supplier_slug, api_key

streamingvex-validate --config pusher.config.json --file my.csaf.json
streamingvex-push --config pusher.config.json --file my.csaf.json --idem-key test-1
```

Expect HTTP `200` and `"status": "accepted"`.

## Part 2 — Subscriber receives webhook

### Configure StreamingVEX

1. Log in as subscriber; subscribe to the catalog entry created by the push.
2. **Webhooks** → add URL `http://127.0.0.1:9000/webhook`, signing secret `dev-secret`.

### Run example receiver

```bash
export WEBHOOK_SECRET=dev-secret
python examples/webhook_receiver/receiver.py --port 9000
```

Trigger delivery: **Force sync** on the catalog product page, or wait for the next poll.

Check `data/received_vex/<catalog_id>/snapshot-*.json`.

Details: [webhook-receiver.md](webhook-receiver.md).

## Next steps

- Harden the receiver (HTTPS, auth, queue workers) using the patterns in `examples/webhook_receiver/verify.py`.
- Automate push in CI: run `streamingvex-validate` in an early job stage, then `streamingvex-push` with secrets for `api_key` and signing PEM.
- Never commit `pusher.config.json`, API keys, or private keys to git.
