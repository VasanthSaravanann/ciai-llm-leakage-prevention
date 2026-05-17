"""Envelope encryption helpers: use AWS KMS if `KMS_KEY_ID` is configured, otherwise fallback to local Fernet.

This module provides `encrypt` and `decrypt` helpers. For KMS use, AWS credentials must
be available in the environment. The fallback is suitable for testing only.
"""
import os
from typing import Tuple

KMS_KEY_ID = os.environ.get('KMS_KEY_ID')

if KMS_KEY_ID:
    try:
        import boto3
        from base64 import b64encode, b64decode
        kms = boto3.client('kms')

        def encrypt(plaintext: bytes) -> Tuple[str, bytes]:
            resp = kms.encrypt(KeyId=KMS_KEY_ID, Plaintext=plaintext)
            return resp['KeyId'], resp['CiphertextBlob']

        def decrypt(ciphertext_blob: bytes) -> bytes:
            resp = kms.decrypt(CiphertextBlob=ciphertext_blob)
            return resp['Plaintext']
    except Exception:
        KMS_KEY_ID = None

if not KMS_KEY_ID:
    # Fallback: use cryptography.Fernet
    from cryptography.fernet import Fernet
    _F = Fernet(Fernet.generate_key())

    def encrypt(plaintext: bytes) -> Tuple[str, bytes]:
        return 'local', _F.encrypt(plaintext)

    def decrypt(ciphertext_blob: bytes) -> bytes:
        return _F.decrypt(ciphertext_blob)
