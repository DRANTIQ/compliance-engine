from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from platform_backend.config.settings import get_settings


def _derive_fernet_key(raw: str) -> bytes:
    if not raw:
        raise ValueError("EXTERNAL_ID_ENCRYPTION_KEY is required to store integrations")
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_external_id(plaintext: str) -> str:
    key = _derive_fernet_key(get_settings().external_id_encryption_key)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_external_id(ciphertext: str) -> str:
    key = _derive_fernet_key(get_settings().external_id_encryption_key)
    try:
        return Fernet(key).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("invalid external_id ciphertext") from exc


def encrypt_credential(plaintext: str) -> str:
    """Encrypt integration secrets (Azure client secret, etc.) — same key as external_id."""
    return encrypt_external_id(plaintext)


def decrypt_credential(ciphertext: str) -> str:
    return decrypt_external_id(ciphertext)
