"""OpenPGP encrypt helper tests."""

from __future__ import annotations

import json

import pytest

pgpy = pytest.importorskip("pgpy")

from streamingvex_tools.pusher.encrypt_openpgp import encrypt_vex_document_openpgp


def _keypair() -> tuple[pgpy.PGPKey, pgpy.PGPKey]:
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("StreamingVEX Test", "test@streamingvex.test")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key, key.pubkey


def test_multi_recipient_encrypt() -> None:
    priv1, pub1 = _keypair()
    priv2, pub2 = _keypair()
    recipients = [
        {"pgp_public_key_armored": str(pub1)},
        {"pgp_public_key_armored": str(pub2)},
    ]
    plaintext = {"document": {"title": "multi"}}
    wrapper = encrypt_vex_document_openpgp(
        plaintext,
        private_key_path=_write_temp_key(priv1),
        passphrase=None,
        recipients=recipients,
        key_id="release-multi",
        plaintext_format="csaf",
    )
    enc = pgpy.PGPMessage.from_blob(wrapper["ciphertext"])
    with priv2.unlock(None):
        decrypted = priv2.decrypt(enc)
    raw = decrypted.message
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    assert json.loads(data.decode()) == plaintext


def test_roundtrip_openpgp_encrypt() -> None:
    priv, pub = _keypair()
    recipients = [{"pgp_public_key_armored": str(pub)}]
    plaintext = {"document": {"title": "test"}}
    wrapper = encrypt_vex_document_openpgp(
        plaintext,
        private_key_path=_write_temp_key(priv),
        passphrase=None,
        recipients=recipients,
        key_id="release-1",
        plaintext_format="csaf",
    )
    assert wrapper["algorithm"] == "OpenPGP"
    enc = pgpy.PGPMessage.from_blob(wrapper["ciphertext"])
    with priv.unlock(None):
        decrypted = priv.decrypt(enc)
    raw = decrypted.message
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    assert json.loads(data.decode()) == plaintext


def _write_temp_key(key: pgpy.PGPKey, tmp_path=None) -> str:
    import tempfile
    from pathlib import Path

    fd, path = tempfile.mkstemp(suffix=".asc")
    Path(path).write_text(str(key), encoding="utf-8")
    return path
