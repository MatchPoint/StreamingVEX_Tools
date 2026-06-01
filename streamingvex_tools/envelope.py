"""Supplier push envelope — wire format for POST /v1/supplier/push."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from pydantic import BaseModel, Field, field_validator, model_validator

from streamingvex_tools.vex_encryption import (
    ContentEncoding,
    is_encrypted_payload,
    parse_encrypted_payload,
)


class SupplierPushEnvelope(BaseModel):
    supplier_slug: str
    vex_document: dict[str, Any]
    content_encoding: ContentEncoding = "json"
    product_name: str | None = None
    product_version: str | None = None
    product_purl: str | None = None
    product_cpe: str | None = None
    software_vendor_name: str | None = None
    pushed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: str | None = None

    @field_validator("content_encoding", mode="before")
    @classmethod
    def _normalize_encoding(cls, value: str | None) -> str:
        return value or "json"

    @model_validator(mode="after")
    def _validate_encrypted_document(self) -> SupplierPushEnvelope:
        if self.content_encoding == "encrypted" or is_encrypted_payload(self.vex_document):
            parse_encrypted_payload(self.vex_document)
            object.__setattr__(self, "content_encoding", "encrypted")
        return self

    def unsigned_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_ed25519_pem(self, private_key_pem: bytes) -> None:
        key = load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Ed25519 private key required")
        sig = key.sign(self.canonical_bytes())
        self.signature = base64.b64encode(sig).decode("ascii")


def verify_envelope_signature(envelope: SupplierPushEnvelope, public_key_pem: str | None) -> bool:
    if not public_key_pem:
        return envelope.signature is None
    if not envelope.signature:
        return False
    key = load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(base64.b64decode(envelope.signature), envelope.canonical_bytes())
        return True
    except InvalidSignature:
        return False
