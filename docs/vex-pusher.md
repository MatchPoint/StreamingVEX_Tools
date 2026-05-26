# VEX Pusher

The **VEX Pusher** (`streamingvex-push` / `vex-pusher`) publishes supplier VEX documents to your StreamingVEX server using `POST /v1/supplier/push`.

## Install

```bash
pip install streamingvex-tools
# or from this repo: pip install -e .
```

## One-time supplier setup

### 1. Account and role approval

1. Register and **verify email** on your StreamingVEX server (`/ui/register`).
2. Request supplier pusher access:

```http
POST /suppliers/request-pusher-access
Authorization: Bearer <jwt>
```

3. Wait for a platform admin to approve (`/ui/admin/supplier-pushers` on the server).
4. Check status: `GET /suppliers/pusher-status` — `role` must be `supplier_pusher`.

### 2. Register supplier and API key

```http
POST /suppliers/register
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "slug": "my-supplier",
  "display_name": "My Organization",
  "signing_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

```http
POST /suppliers/{supplier_id}/credentials
Authorization: Bearer <jwt>
```

Save `api_key` (`svx_…`) — shown **once**.

### 3. Signing keys (recommended)

```bash
openssl genpkey -algorithm Ed25519 -out supplier-private.pem
openssl pkey -in supplier-private.pem -pubout -out supplier-public.pem
```

Register the public PEM at supplier registration. Reference the private PEM in config as `signing_key_pem`.

## Configuration

Copy `examples/pusher.config.example.json`:

```json
{
  "base_url": "https://your-streamingvex-server.example.com",
  "supplier_slug": "my-supplier",
  "api_key": "svx_...",
  "signing_key_pem": "./supplier-private.pem",
  "product_name": "My Product",
  "product_version": "1.0.0"
}
```

Add to `.gitignore`: `pusher.config.json`, `*.pem`.

## Push a release

```bash
streamingvex-push \
  --config pusher.config.json \
  --file releases/my-product.csaf.json \
  --idem-key release-202602
```

Success (HTTP 200):

```json
{
  "status": "accepted",
  "snapshot_id": 42,
  "catalog_source_id": 1,
  "authenticity_tier": "supplier_signed"
}
```

## CLI flags

| Flag | Description |
|------|-------------|
| `--config` | JSON config path |
| `--file` | VEX JSON file (stdin if omitted) |
| `--base-url` | Server URL |
| `--supplier-slug`, `--api-key` | Credentials |
| `--product-name`, `--product-version`, `--product-purl`, `--product-cpe` | Catalog metadata |
| `--signing-key-pem` | Ed25519 private key |
| `--content-encoding` | `json` or `encrypted` |
| `--idem-key` | Idempotency-Key header |

## Encrypted VEX

Set `content_encoding` to `encrypted` and use this wrapper in `vex_document`:

```json
{
  "streamingvex_encrypted_vex": "1",
  "algorithm": "AES-256-GCM",
  "key_id": "release-key-id",
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "plaintext_format": "csaf"
}
```

Always include `product_name` and `product_version` on the envelope.

## Troubleshooting

| Symptom | Action |
|---------|--------|
| `403 supplier pusher role required` | Request access; wait for admin approval |
| `403 invalid supplier api key` | Regenerate credentials |
| `403 invalid or missing document signature` | Check signing key PEM and registered public key |
| `duplicate` | Same `--idem-key` or identical content already ingested |

## Wire format

The CLI builds a **SupplierPushEnvelope** JSON object (see `streamingvex_tools/envelope.py` in this repo). Server API contract:

```http
POST /v1/supplier/push
X-Supplier-API-Key: svx_...
Idempotency-Key: <optional>
Content-Type: application/json
```
