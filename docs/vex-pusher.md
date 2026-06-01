# VEX Pusher — supplier CLI reference

The **VEX Pusher** (`streamingvex-push` / `vex-pusher`) and **VEX Validate** (`streamingvex-validate`) are public client tools for publishing supplier VEX to StreamingVEX via `POST /v1/supplier/push`.

This guide is the **canonical reference** for configuration, catalog readiness, plaintext vs encrypted publish, validation, and troubleshooting. The StreamingVEX **Source assistant** is trained on this document and related user guides in the StreamingVEX server repo.

---

## Commands

| Command | Purpose | Needs API key? |
|---------|---------|----------------|
| `streamingvex-validate` | Check catalog readiness locally | No |
| `streamingvex-push` | Validate (by default), then push | Yes |
| `streamingvex-push validate …` | Same as validate subcommand | No |
| `streamingvex-push --validate …` | Validate-only via push entrypoint | No |

Install:

```bash
git clone https://github.com/MatchPoint/StreamingVEX_tools.git
cd StreamingVEX_tools
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Core concepts

### Supplier push vs public pull

| Model | Who | Typical use |
|-------|-----|-------------|
| **Supplier push** (`streamingvex-push`) | Registered supplier with approved pusher role | You **are** the product vendor (or publish on their behalf with matching `software_vendor_name`) |
| **Public pull** (`/ui/catalog/add-public`) | Any verified user; admin approves | Third-party mirrors of OSS VEX (e.g. community CSAF for another vendor's product) |

**Important:** A supplier registered for vendor **AMI** cannot supplier-push TianoCore EDK II VEX — the server returns **HTTP 422** (product supplier mismatch). Use **public pull** for third-party OSS catalogs instead. See [StreamingVEX push sources — authorization](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/push-sources.md).

### Three identities (do not confuse them)

| Name | Config / envelope field | Meaning |
|------|-------------------------|---------|
| **VEX publisher** | `supplier_slug` | Your identity on StreamingVEX (who pushes). Must match the API key's supplier. |
| **Product supplier / software vendor** | `software_vendor_name` (envelope) or CSAF `product_tree` vendor | Who makes the software the VEX describes (e.g. TianoCore for EDK II). |
| **VEX publisher display** | `display_name` at registration | Human-readable org name; may differ from slug. |

Example: slug `matchpoint-vex4edk2` publishing TianoCore EDK II is a **third-party** catalog relationship when done via **public pull**, not supplier push.

### Envelope vs VEX document

The CLI sends a **SupplierPushEnvelope**, not raw VEX alone:

| Layer | Contents |
|-------|----------|
| **Envelope** | `supplier_slug`, optional `product_*`, `software_vendor_name`, `content_encoding`, optional Ed25519 `signature` |
| **`vex_document`** | OpenVEX, CSAF, CycloneDX, SPDX JSON — **or** an encrypted wrapper (ciphertext) |

Envelope fields are used for **catalog indexing**. For plaintext VEX, many fields can be **extracted from the file**. For encrypted VEX, the server **cannot read ciphertext**, so envelope metadata is **mandatory**.

### Two different private keys

| Key | Config / flag | Algorithm | Purpose |
|-----|---------------|-----------|---------|
| **Signing key** | `signing_key_pem` / `--signing-key-pem` | Ed25519 | Proves envelope integrity to StreamingVEX (optional but recommended if registered) |
| **Encryption key** | `encryption_key_file` / `--encryption-key-file` | AES-256-GCM (32 bytes) | Protects VEX **content** for subscribers; StreamingVEX never sees plaintext |

Never commit either key or `api_key` to git. Add `pusher.config.json`, `*.pem`, and `*.key` to `.gitignore`.

---

## One-time supplier setup

### 1. Account and pusher role

1. Register and **verify email** at `/ui/register`.
2. Apply at **`/ui/supplier-pusher`** with supplier slug, company name, and supplier website (email domain must match website domain).
3. Platform admin approves at **`/ui/admin/supplier-pushers`**. You receive an **email** when approved or denied.
4. Open **`/ui/supplier`**, register your slug, and create an API key (`svx_…` — shown **once**).

REST equivalents:

```http
POST /suppliers/request-pusher-access
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "intended_supplier_slug": "my-supplier",
  "company_name": "My Organization",
  "supplier_website": "https://www.example.com"
}
```

```http
POST /suppliers/register
Authorization: Bearer <jwt>

{
  "slug": "my-supplier",
  "display_name": "My Organization",
  "software_vendor_name": "My Organization",
  "signing_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

`software_vendor_name` at registration must match the **product supplier** in VEX you intend to push.

### 2. Signing keys (recommended)

```bash
openssl genpkey -algorithm Ed25519 -out supplier-private.pem
openssl pkey -in supplier-private.pem -pubout -out supplier-public.pem
```

Register `supplier-public.pem` at supplier registration. Set `"signing_key_pem": "./supplier-private.pem"` in config.

If a public key is registered, every push must include a valid envelope **signature**.

---

## Configuration file (`pusher.config.json`)

Copy `examples/pusher.config.example.json`. The format supports **`//` line comments** (JSONC-style). When uncommenting optional lines, **add a comma** after the previous property.

### Minimum config (plaintext VEX with embedded metadata)

Use this when each `--file` is a CSAF/OpenVEX document that already includes product identity (typical for EDK II CSAF with `product_tree`):

```json
{
  "base_url": "http://127.0.0.1:8000",
  "supplier_slug": "my-supplier",
  "api_key": "svx_..."
}
```

Push many releases with one config — metadata comes from each file:

```bash
for f in vex/edk2-stable*.csaf.json; do
  streamingvex-push --config pusher.config.json --file "./$f" --idem-key "${f%.csaf.json}"
done
```

### Full config reference

| Field | Required? | Purpose |
|-------|-----------|---------|
| `base_url` | **Yes** | StreamingVEX server URL (no trailing slash) |
| `supplier_slug` | **Yes** (push) | Registered publisher slug |
| `api_key` | **Yes** (push) | Supplier API key `svx_…` |
| `product_name` | Optional* | Catalog product name; overrides VEX |
| `product_version` | Optional* | Catalog release/version; overrides VEX |
| `software_vendor_name` | Optional* | Product supplier on envelope; required for encrypted |
| `product_purl` | Optional | SBOM matching |
| `product_cpe` | Optional | CVE/SBOM correlation |
| `signing_key_pem` | Optional | Ed25519 private PEM path for envelope signature |
| `content_encoding` | Optional | `json` (default) or `encrypted` |
| `encryption_key_file` | With `--encrypt` | 32-byte AES key file (raw or base64 text) |
| `encryption_key_id` | With `--encrypt` | Subscriber key id (distributed out-of-band) |

\*See **Catalog readiness** below — required when not extractable from VEX; **always required on envelope for encrypted VEX**.

CLI flags override config values for the same fields.

### Override example

```json
{
  "base_url": "https://vex.example.com",
  "supplier_slug": "acme-firmware",
  "api_key": "svx_...",
  "signing_key_pem": "./supplier-private.pem",
  "product_name": "ACME Firmware",
  "product_version": "2.4.1",
  "software_vendor_name": "ACME Corp",
  "product_cpe": "cpe:2.3:o:acme:firmware:2.4.1:*:*:*:*:*:*:*"
}
```

**Warning:** Fixed `product_name` / `product_version` in config **override every push**. Do not use fixed product fields when pushing multiple different releases from one config unless you pass per-invocation CLI overrides.

---

## Catalog readiness

Before any push, the CLI runs the same checks the server uses for **catalog readiness** (HTTP **422** on failure).

Run explicitly without credentials:

```bash
streamingvex-validate --file ./my.csaf.json
streamingvex-validate --config pusher.config.json --file ./my.csaf.json
streamingvex-validate --file ./my.csaf.json --json
```

### Plaintext VEX (`content_encoding: json`)

| Check | Error if missing? | Source priority |
|-------|-------------------|-----------------|
| Recognizable format | Yes | OpenVEX, CSAF, CycloneDX, SPDX |
| Document structure | Yes | e.g. CSAF `document.tracking`, `vulnerabilities[]` |
| `product_name` | Yes if nowhere else | Envelope/config **overrides** CSAF/OpenVEX extraction |
| `product_version` | Warning only | Strongly recommended for subscriptions/SBOM |
| `product_purl` / `product_cpe` | Warning if both missing | Improves auto-subscribe from SBOM |
| `software_vendor_name` | Validated against registration at server | From CSAF vendor branch or envelope |

**CSAF example:** `product_tree` vendor → `software_vendor_name`; product name/version branches → `product_name`, `product_version`; `product_id` → CPE.

**OpenVEX example:** product PURL in `statements[].products` → name/version.

### Encrypted VEX (`content_encoding: encrypted`)

The server **does not decrypt**. These envelope fields are **required**:

| Field | Required |
|-------|----------|
| `product_name` | **Yes** |
| `product_version` | **Yes** |
| `software_vendor_name` | **Yes** (when supplier scope is checked) |
| Valid encrypted wrapper | **Yes** |

If you push a pre-built ciphertext file without envelope metadata, validation **fails** and the CLI prints recommended flags:

```text
Encrypted VEX requires catalog metadata on the push envelope (config or CLI flags):
  --product-name "My Product"
  --product-version "1.0.0"
  --software-vendor-name "My Vendor"
  ...

Or push cleartext and let the pusher validate, extract metadata, and encrypt:
  --encrypt --encryption-key-file ./vex-aes256.key --encryption-key-id release-202411
```

---

## Push workflows

### Standard plaintext push

```bash
streamingvex-push \
  --config pusher.config.json \
  --file ./edk2-stable202411.csaf.json \
  --idem-key edk2-stable202411
```

Success (HTTP 200):

```json
{
  "status": "accepted",
  "snapshot_id": 42,
  "catalog_source_id": 1,
  "authenticity_tier": "supplier_signed",
  "content_encoding": "json",
  "product_name": "EDK II",
  "product_version": "edk2-stable202411"
}
```

### Idempotency (`--idem-key`)

Sets HTTP header `Idempotency-Key`. Use a **stable value per release artifact** (e.g. `edk2-stable202411`) so retries and CI re-runs do not create duplicate snapshots.

| Behavior | Condition |
|----------|-----------|
| New ingest | First push with this key |
| Idempotent replay | Same source + same `Idempotency-Key` |
| Duplicate hash | Same content SHA256 even without key |

Optional but recommended for production and CI.

### Encrypted push — recommended (`--encrypt`)

Let the pusher validate cleartext, **extract metadata**, encrypt, and fill the envelope:

```bash
# Generate 32-byte AES key once; share with subscribers out-of-band
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())" > vex-aes256.key

streamingvex-push \
  --config pusher.config.json \
  --file ./edk2-stable202411.csaf.json \
  --encrypt \
  --encryption-key-file ./vex-aes256.key \
  --encryption-key-id edk2-stable202411 \
  --idem-key edk2-stable202411
```

Steps performed internally:

1. Parse cleartext CSAF/OpenVEX from `--file`
2. Run catalog readiness on plaintext
3. Copy extracted `product_name`, `product_version`, `software_vendor_name`, CPE/PURL to envelope (unless already in config/CLI)
4. Encrypt document body with **AES-256-GCM** using `encryption_key_file`
5. Build wrapper with `plaintext_format` set from detected format (`csaf`, `openvex`, …)
6. Push with `content_encoding: encrypted`

Validate the encrypt path without pushing:

```bash
streamingvex-validate \
  --config pusher.config.json \
  --file ./edk2-stable202411.csaf.json \
  --encrypt \
  --encryption-key-file ./vex-aes256.key \
  --encryption-key-id edk2-stable202411
```

### Encrypted push — manual wrapper

If you built ciphertext yourself, supply all envelope metadata explicitly:

```bash
streamingvex-push \
  --config pusher.config.json \
  --file ./release.enc.json \
  --content-encoding encrypted \
  --product-name "EDK II" \
  --product-version edk2-stable202411 \
  --software-vendor-name TianoCore \
  --idem-key edk2-stable202411
```

Wrapper schema in `vex_document`:

```json
{
  "streamingvex_encrypted_vex": "1",
  "algorithm": "AES-256-GCM",
  "key_id": "edk2-stable202411",
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "plaintext_format": "csaf"
}
```

Subscribers decrypt locally using the key matching `key_id`. StreamingVEX stores and forwards ciphertext only.

---

## CLI flags (complete)

| Flag | Validate | Push | Description |
|------|:--------:|:----:|-------------|
| `--config` | ✓ | ✓ | Path to `pusher.config.json` |
| `--file` | ✓ | ✓ | VEX JSON path (stdin if omitted) |
| `--json` | ✓ | — | JSON readiness report |
| `--product-name` | ✓ | ✓ | Envelope product name |
| `--product-version` | ✓ | ✓ | Envelope product version |
| `--software-vendor-name` | ✓ | ✓ | Product supplier on envelope |
| `--product-purl` | ✓ | ✓ | Package URL |
| `--product-cpe` | ✓ | ✓ | CPE string |
| `--content-encoding` | ✓ | ✓ | `json` or `encrypted` |
| `--encrypt` | ✓ | ✓ | Encrypt cleartext `--file` before push |
| `--encryption-key-file` | ✓ | ✓ | AES-256 key file (32 bytes raw or base64) |
| `--encryption-key-id` | ✓ | ✓ | Subscriber key identifier |
| `--base-url` | — | ✓ | Override server URL |
| `--supplier-slug` | — | ✓ | Override slug |
| `--api-key` | — | ✓ | Override API key |
| `--signing-key-pem` | — | ✓ | Ed25519 envelope signing key |
| `--idem-key` | — | ✓ | Idempotency-Key header |
| `--validate` | — | ✓ | Validate only (no HTTP push) |
| `--validate-json` | — | ✓ | JSON report via push entrypoint |

---

## Shell and path tips

### WSL / Linux

Use **forward slashes** or **relative paths**. Unquoted Windows backslashes are eaten by bash:

```bash
# Wrong in WSL (path corrupted)
--file c:\Users\me\vex\file.csaf.json

# Right
--file ./edk2-stable202411.csaf.json
--file /mnt/c/Users/me/vex/edk2-stable202411.csaf.json
```

### JSON config commas

When uncommenting optional fields in `pusher.config.json`, ensure a **comma** after the preceding line. The loader reports line/column on parse errors.

---

## CI integration

```yaml
# Example job fragment
- name: Validate VEX
  run: streamingvex-validate --file releases/${{ matrix.release }}.csaf.json

- name: Push VEX
  env:
    SVX_API_KEY: ${{ secrets.STREAMINGVEX_SUPPLIER_KEY }}
  run: |
    streamingvex-push \
      --config pusher.config.json \
      --file releases/${{ matrix.release }}.csaf.json \
      --idem-key "${{ matrix.release }}"
```

Store `api_key`, `signing_key_pem`, and encryption keys in CI secrets — not in the repo.

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `command not found` | Tools not installed in active venv | `pip install -e .` and `source .venv/bin/activate` |
| `JSONDecodeError` in config | Missing comma in `pusher.config.json` | Fix JSON; see error line number |
| `FileNotFoundError` for `--file` | Bad path (especially WSL backslashes) | Use `./file.json` or `/mnt/c/...` |
| CLI exit `1` before HTTP | Local catalog readiness failed | Read stderr report; run `streamingvex-validate` |
| `403 supplier pusher role required` | Role not approved | Complete `/ui/supplier-pusher` flow |
| `403 invalid supplier api key` | Wrong key or slug mismatch | Regenerate at `/ui/supplier` |
| `403 invalid or missing document signature` | Signing key required but missing/invalid | Check `signing_key_pem` and registered public key |
| `422` product supplier mismatch | VEX vendor ≠ registered `software_vendor_name` | Fix registration or use **public pull** for third-party OSS |
| `422 catalog readiness` | Missing metadata or bad format | Run `streamingvex-validate --file …` |
| `duplicate` | Same `--idem-key` or identical content | Expected on retry; use stable idem keys intentionally |
| Encrypted push missing fields | Pushing wrapper without envelope metadata | Use `--encrypt` from cleartext or add `--product-*` flags |

Subscriber-side delivery: use `/ui/delivery-log` and the [webhook receiver guide](webhook-receiver.md).

---

## Wire format

```http
POST /v1/supplier/push
X-Supplier-API-Key: svx_...
Idempotency-Key: edk2-stable202411
Content-Type: application/json
```

Body: `SupplierPushEnvelope` JSON (see `streamingvex_tools/envelope.py`). Server contract documented in [StreamingVEX push sources](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/push-sources.md).

---

## Related documentation

| Document | Location |
|----------|----------|
| Getting started (push + webhook E2E) | [getting-started.md](getting-started.md) |
| Webhook receiver example | [webhook-receiver.md](webhook-receiver.md) |
| Server push API & encrypted schema | [StreamingVEX push sources](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/push-sources.md) |
| Server-side pusher example | [StreamingVEX vex-pusher-example](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/vex-pusher-example.md) |
| Public pull (third-party OSS) | [StreamingVEX pull sources](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/pull-sources.md) |

---

## Tests

```bash
pytest tests/test_validate.py tests/test_encrypt.py tests/test_pusher.py -v
```

Covers catalog readiness, encryption round-trip, config loading, CLI subprocess behavior, and envelope signing.
