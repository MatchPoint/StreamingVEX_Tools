"""Encrypt cleartext VEX for supplier push (AES-256-GCM)."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from streamingvex_tools.vex_encryption import EncryptedVexPayload


def load_aes256_key(key_path: str | Path) -> bytes:
    """Load a 32-byte AES-256 key from a file (raw bytes or base64 text)."""

    raw = Path(key_path).read_bytes()
    if len(raw) == 32:
        return raw
    text = raw.decode("utf-8").strip()
    if not text:
        raise ValueError(f"encryption key file is empty: {key_path}")
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError(
            f"encryption key file must contain 32 raw bytes or base64-encoded 32-byte key: {key_path}"
        ) from exc
    if len(decoded) != 32:
        raise ValueError(
            f"encryption key must be 32 bytes after decoding (got {len(decoded)}): {key_path}"
        )
    return decoded


def encrypt_vex_document(
    plaintext: dict[str, Any],
    *,
    key_path: str | Path,
    key_id: str,
    plaintext_format: str | None,
) -> dict[str, Any]:
    """Validate cleartext JSON, encrypt it, and return the StreamingVEX wrapper dict."""

    if not key_id.strip():
        raise ValueError("encryption key_id is required")
    key = load_aes256_key(key_path)
    body = json.dumps(plaintext, sort_keys=True, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, body, None)
    wrapper = EncryptedVexPayload(
        algorithm="AES-256-GCM",
        key_id=key_id.strip(),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        plaintext_format=plaintext_format,
    )
    return wrapper.model_dump()
