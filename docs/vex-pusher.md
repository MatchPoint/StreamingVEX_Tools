# VEX Pusher

The **VEX Pusher** (`streamingvex-push` / `vex-pusher`) publishes supplier VEX documents to your StreamingVEX server using `POST /v1/supplier/push`.

## Install

```bash
pip install streamingvex-tools
# or from this repo: pip install -e .
```

Commands: **`streamingvex-push`** / `vex-pusher` (push), **`streamingvex-validate`** (validate-only).

## One-time supplier setup

### 1. Account and role approval

1. Register and **verify email** (`/ui/register`).
2. Submit an application at **`/ui/supplier-pusher`** with supplier slug, company name, and supplier website (or use the JSON API below).
3. Wait for platform admin approval at `/ui/admin/supplier-pushers` — you receive an **email** when approved or denied.
4. When approved, open **`/ui/supplier`** to register your slug and create an API key.

```http
POST /suppliers/request-pusher-access
Authorization: Bearer <jwt>

{
  "intended_supplier_slug": "my-supplier",
  "company_name": "My Organization",
  "supplier_website": "https://www.example.com"
}
```

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

### Authorization scope

- A supplier API key works **only** with the matching `supplier_slug` in the push envelope — you cannot push as another publisher.
- Under your slug, you may push **any product/version** that passes catalog readiness; there is **no per-product allowlist**.
- Third-party VEX (your slug, another vendor's product in the document) is allowed; the catalog marks it **third_party**.
- User API keys (`svx_u_…`) are a different credential — they push to **your own sources** via `/v1/ingest/{id}`, not the supplier catalog path.

See the StreamingVEX user guide [Push sources — authorization and scope](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/push-sources.md#authorization-and-scope-supplier-api-keys) for full detail.

### 3. Signing keys (recommended)

```bash
openssl genpkey -algorithm Ed25519 -out supplier-private.pem
openssl pkey -in supplier-private.pem -pubout -out supplier-public.pem
```

Register the public PEM at supplier registration. Reference the private PEM in config as `signing_key_pem`.

## Configuration

Copy `examples/pusher.config.example.json` to `pusher.config.json`. The example uses `//` comments (required vs optional). Optional fields are commented out by default — uncomment as needed.

```json
{
  // REQUIRED: StreamingVEX server URL
  "base_url": "https://your-streamingvex-server.example.com",
  "supplier_slug": "my-supplier",
  "api_key": "svx_...",
  "product_name": "My Product",
  "product_version": "1.0.0",
  // OPTIONAL: "product_purl": "pkg:generic/my-product@1.0.0",
  // OPTIONAL: "product_cpe": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
  // OPTIONAL: "signing_key_pem": "./supplier-private.pem"
}
```

Add to `.gitignore`: `pusher.config.json`, `*.pem`.

## Validate before push

Check that a VEX file has enough metadata for the StreamingVEX catalog **without** contacting the server (no `api_key` required):

```bash
streamingvex-validate --file releases/my-product.csaf.json

# Merge optional product overrides from config
streamingvex-validate --config pusher.config.json --file releases/my-product.csaf.json

# Equivalent via the pusher
streamingvex-push validate --file releases/my-product.csaf.json
streamingvex-push --validate --file releases/my-product.csaf.json

# JSON output for CI
streamingvex-validate --file my.csaf.json --json
```

Every push runs the same check first. The server rejects invalid envelopes with HTTP **422**.

| Result | Action |
|--------|--------|
| Exit `0`, `Catalog readiness: OK` | Safe to push |
| Exit `1`, errors in report | Fix format or add `product_name` / `product_version` (required for encrypted VEX) |
| Warnings only | Push allowed; add `product_version`, `product_purl`, or `product_cpe` for better SBOM matching |

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
| `--supplier-slug`, `--api-key` | Credentials (push only) |
| `--product-name`, `--product-version`, `--product-purl`, `--product-cpe` | Catalog metadata |
| `--signing-key-pem` | Ed25519 private key |
| `--content-encoding` | `json` or `encrypted` |
| `--idem-key` | Idempotency-Key header |
| `--validate` | Validate only — do not push |
| `--validate-json` | With `--validate`, print JSON (push CLI) |
| `--json` | JSON output (`streamingvex-validate` / `streamingvex-push validate`) |

**Validate-only:** `streamingvex-validate --file …` or `streamingvex-push validate --file …`.

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
| `422 catalog readiness validation failed` | Run `streamingvex-validate --file …` locally |
| CLI exit `1` before HTTP | Local validation failed — see stderr |

## Wire format

The CLI builds a **SupplierPushEnvelope** JSON object (see `streamingvex_tools/envelope.py` in this repo). Server API contract:

```http
POST /v1/supplier/push
X-Supplier-API-Key: svx_...
Idempotency-Key: <optional>
Content-Type: application/json
```
