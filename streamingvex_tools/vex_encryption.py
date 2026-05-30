"""Encrypted VEX wire format — suppliers publish ciphertext; subscribers decrypt locally."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

ENCRYPTED_VEX_MARKER = "1"
ContentEncoding = Literal["json", "encrypted"]


class EncryptedVexPayload(BaseModel):
    streamingvex_encrypted_vex: str = Field(default=ENCRYPTED_VEX_MARKER)
    algorithm: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)
    nonce: str | None = None
    plaintext_format: str | None = None

    @model_validator(mode="after")
    def _marker(self) -> EncryptedVexPayload:
        if self.streamingvex_encrypted_vex != ENCRYPTED_VEX_MARKER:
            raise ValueError("streamingvex_encrypted_vex must be '1'")
        return self


def is_encrypted_payload(payload: dict[str, Any]) -> bool:
    return payload.get("streamingvex_encrypted_vex") == ENCRYPTED_VEX_MARKER


def parse_encrypted_payload(payload: dict[str, Any]) -> EncryptedVexPayload:
    return EncryptedVexPayload.model_validate(payload)


def resolve_content_encoding(
    payload: dict[str, Any],
    *,
    declared: str | None = None,
) -> ContentEncoding:
    if declared == "encrypted" or is_encrypted_payload(payload):
        return "encrypted"
    return "json"
