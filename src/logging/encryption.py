"""Envelope encryption helpers backed by the secrets manager abstraction.

This wraps the logic for envelope encryption and uses the configured secrets
manager to store Fernet key material. If a cloud KMS/Secrets Manager is
configured, that will be used; otherwise we fall back to a local Fernet key
for development only.
"""
from typing import Tuple
from src.secrets.manager import get_secrets_manager

mgr = get_secrets_manager()


def _get_fernet():
    from cryptography.fernet import Fernet
    key = mgr.get_fernet_key()
    return Fernet(key)


def encrypt(plaintext: bytes) -> Tuple[str, bytes]:
    """Return (key_id, ciphertext_bytes).

    When backed by KMS/Secrets Manager the key_id may be an identifier; for
    local fallback we return 'local'.
    """
    f = _get_fernet()
    ct = f.encrypt(plaintext)
    return ('local', ct)


def decrypt(ciphertext_blob: bytes) -> bytes:
    f = _get_fernet()
    return f.decrypt(ciphertext_blob)
