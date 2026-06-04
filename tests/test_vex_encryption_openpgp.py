"""OpenPGP profile validation in tools vex_encryption module."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from streamingvex_tools.vex_encryption import EncryptedVexPayload, parse_encrypted_payload


def test_openpgp_wrapper_parses() -> None:
    payload = parse_encrypted_payload(
        {
            "streamingvex_encrypted_vex": "1",
            "algorithm": "OpenPGP",
            "key_id": "rel-1",
            "ciphertext": "-----BEGIN PGP MESSAGE-----\n\nhQIMAw\n-----END PGP MESSAGE-----",
        }
    )
    assert payload.algorithm == "OpenPGP"
    assert payload.nonce is None


def test_openpgp_rejects_invalid_algorithm() -> None:
    with pytest.raises(ValidationError):
        EncryptedVexPayload(
            algorithm="ChaCha20-Poly1305",
            key_id="k",
            ciphertext="x",
        )
