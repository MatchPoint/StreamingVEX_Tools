"""OpenPGP multi-recipient encrypt for supplier push."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from streamingvex_tools.vex_encryption import EncryptedVexPayload


def load_private_key_armored(path: str | Path) -> str:
    text = Path(path).read_text(encoding="utf-8")
    if "BEGIN PGP PRIVATE KEY BLOCK" not in text and "BEGIN PGP SECRET KEY BLOCK" not in text:
        raise ValueError(f"not an armored private key file: {path}")
    return text.strip()


def load_passphrase(path: str | Path | None) -> str | None:
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8").strip() or None


def _unlock_private_key(priv_key: Any, passphrase: str | None) -> None:
    if passphrase:
        with priv_key.unlock(passphrase):
            return
    if priv_key.is_protected:
        raise ValueError("private key is protected; provide --pgp-passphrase-file")
    with priv_key.unlock(None):
        return


def _encrypt_to_recipients(message: Any, pub_keys: list[Any]) -> Any:
    from pgpy.constants import SymmetricKeyAlgorithm

    if not pub_keys:
        raise ValueError("no recipient public keys")

    cipher = SymmetricKeyAlgorithm.AES256
    sessionkey = cipher.gen_key()
    try:
        enc_msg = pub_keys[0].encrypt(message, cipher=cipher, sessionkey=sessionkey)
        for pk in pub_keys[1:]:
            enc_msg = pk.encrypt(enc_msg, cipher=cipher, sessionkey=sessionkey)
        return enc_msg
    finally:
        del sessionkey


def encrypt_vex_document_openpgp(
    plaintext: dict[str, Any],
    *,
    private_key_path: str | Path,
    passphrase: str | None,
    recipients: list[dict[str, Any]],
    key_id: str,
    plaintext_format: str | None,
) -> dict[str, Any]:
    """Encrypt cleartext VEX JSON to approved recipient public keys."""

    try:
        import pgpy
    except ImportError as exc:
        raise RuntimeError("pgpy is required for --encrypt-openpgp; pip install pgpy") from exc

    if not key_id.strip():
        raise ValueError("encryption key_id is required (release label)")

    priv_key, _ = pgpy.PGPKey.from_blob(load_private_key_armored(private_key_path))
    _unlock_private_key(priv_key, passphrase)

    pub_keys = []
    for rec in recipients:
        armored = rec.get("pgp_public_key_armored") or ""
        pk, _ = pgpy.PGPKey.from_blob(armored)
        if not pk.is_public:
            raise ValueError("recipient key material must be a public key")
        pub_keys.append(pk)

    body = json.dumps(plaintext, sort_keys=True, separators=(",", ":")).encode("utf-8")
    message = pgpy.PGPMessage.new(body)
    encrypted = _encrypt_to_recipients(message, pub_keys)
    ciphertext = str(encrypted)

    wrapper = EncryptedVexPayload(
        algorithm="OpenPGP",
        key_id=key_id.strip(),
        ciphertext=ciphertext,
        plaintext_format=plaintext_format,
    )
    return wrapper.model_dump()
