# Getting started

End-to-end **local** test: supplier pushes VEX with StreamingVEX Tools, subscriber receives a webhook. Assumes a StreamingVEX server (example `http://127.0.0.1:8000`).

**Full CLI reference:** [vex-pusher.md](vex-pusher.md) — configuration, catalog readiness, plaintext vs encrypted publish, troubleshooting.

---

## Prerequisites

- Python **3.11+**
- Running StreamingVEX server
- Two accounts: **supplier** (approved pusher) and **subscriber**
- Install tools:

```bash
git clone https://github.com/MatchPoint/StreamingVEX_tools.git
cd StreamingVEX_tools
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,webhook]"
```

---

## Part 1 — Supplier pushes VEX

### Account and approval

1. Register and verify email (`/ui/register`).
2. Apply at **`/ui/supplier-pusher`** — supplier slug, company name, supplier website (email domain must match website).
3. Admin approves at **`/ui/admin/supplier-pushers`** (email notification).
4. Register supplier + API key at **`/ui/supplier`**. Save `svx_…` — shown once.

At registration, set **`software_vendor_name`** to the product supplier you will push VEX for (must match CSAF/OpenVEX vendor metadata).

### Configure pusher

```bash
cp examples/pusher.config.example.json pusher.config.json
```

Minimum config when your VEX file embeds product metadata (typical CSAF):

```json
{
  "base_url": "http://127.0.0.1:8000",
  "supplier_slug": "my-supplier",
  "api_key": "svx_..."
}
```

See [vex-pusher.md — Configuration](vex-pusher.md#configuration-file-pusherconfigjson) for all fields.

### Validate then push

```bash
streamingvex-validate --config pusher.config.json --file my.csaf.json
streamingvex-push --config pusher.config.json --file my.csaf.json --idem-key test-1
```

Expect HTTP `200` and `"status": "accepted"`.

### Optional: encrypted publish

```bash
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())" > vex-aes256.key

streamingvex-push \
  --config pusher.config.json \
  --file my.csaf.json \
  --encrypt \
  --encryption-key-file ./vex-aes256.key \
  --encryption-key-id test-release-1 \
  --idem-key test-1
```

The pusher validates cleartext, extracts catalog fields, encrypts, and pushes. Details: [vex-pusher.md — Encrypted push](vex-pusher.md#encrypted-push--recommended-encrypt).

---

## Part 2 — Subscriber receives webhook

### Configure StreamingVEX

1. Log in as subscriber; subscribe to the catalog entry created by the push.
2. **Webhooks** → URL `http://127.0.0.1:9000/webhook`, secret `dev-secret`.

### Run example receiver

```bash
export WEBHOOK_SECRET=dev-secret
python examples/webhook_receiver/receiver.py --port 9000
```

Trigger delivery: **Force sync** on the catalog page, or wait for poll.

Received events: `data/received_vex/<catalog_id>/snapshot-*.json`.

Details: [webhook-receiver.md](webhook-receiver.md).

---

## Third-party OSS VEX (not supplier push)

If you mirror another vendor's product (e.g. community CSAF for upstream firmware you do not supply), **do not** use `streamingvex-push`. Register URLs at **`/ui/catalog/add-public`** on the StreamingVEX server and wait for admin approval. See [StreamingVEX pull sources](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/pull-sources.md).

---

## Next steps

- Production: HTTPS webhooks, CI secrets, stable `--idem-key` per release.
- Read [vex-pusher.md](vex-pusher.md) for batch pushes, signing keys, and troubleshooting.
- Never commit `pusher.config.json`, API keys, or key material.
