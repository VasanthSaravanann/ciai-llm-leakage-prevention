"""Secrets manager abstraction supporting AWS KMS, Vault, and local Fernet fallback.

This module provides a simple interface to store/retrieve secrets and to manage
Fernet key material for envelope encryption. It prefers KMS when configured,
then Vault, and finally falls back to an in-memory/local file-backed Fernet key
for development only.

Usage:
    from src.secrets.manager import get_secrets_manager
    mgr = get_secrets_manager()
    key = mgr.get_fernet_key()
    mgr.put_secret('providers/openai', json.dumps({...}))
"""
import os
import json
from typing import Optional


class BaseSecretsManager:
    backend_name: str = "base"

    def get_secret(self, name: str) -> Optional[str]:
        raise NotImplementedError()

    def put_secret(self, name: str, value: str) -> None:
        raise NotImplementedError()

    def get_fernet_key(self) -> bytes:
        raise NotImplementedError()

    def rotate_fernet_key(self) -> bytes:
        """Generate and persist a new Fernet key, returning the new key bytes."""
        raise NotImplementedError()


class KMSSecretsManager(BaseSecretsManager):
    backend_name = "kms"

    def __init__(self, kms_key_id: str):
        import boto3
        from base64 import b64encode, b64decode
        self.kms = boto3.client('kms')
        self.kms_key_id = kms_key_id
        # For storing Fernet key material, we use a simple SSM Parameter or Secrets Manager key name
        self.fernet_secret_name = os.getenv('FERNET_SECRET_NAME', 'ciai/fernet_key')

    def get_secret(self, name: str) -> Optional[str]:
        # Use AWS Secrets Manager
        try:
            import boto3
            client = boto3.client('secretsmanager')
            resp = client.get_secret_value(SecretId=name)
            return resp.get('SecretString')
        except Exception:
            return None

    def put_secret(self, name: str, value: str) -> None:
        import boto3
        client = boto3.client('secretsmanager')
        try:
            client.put_secret_value(SecretId=name, SecretString=value)
        except Exception:
            # try create
            client.create_secret(Name=name, SecretString=value)

    def get_fernet_key(self) -> bytes:
        try:
            import boto3
            client = boto3.client('secretsmanager')
            resp = client.get_secret_value(SecretId=self.fernet_secret_name)
            key_b64 = resp.get('SecretString')
            return key_b64.encode('utf-8')
        except Exception:
            # As fallback, generate local
            return self.rotate_fernet_key()

    def rotate_fernet_key(self) -> bytes:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        # store in secrets manager
        try:
            import boto3
            client = boto3.client('secretsmanager')
            client.put_secret_value(SecretId=self.fernet_secret_name, SecretString=key.decode('utf-8'))
        except Exception:
            try:
                client.create_secret(Name=self.fernet_secret_name, SecretString=key.decode('utf-8'))
            except Exception:
                pass
        return key


class VaultSecretsManager(BaseSecretsManager):
    backend_name = "vault"

    def __init__(self, url: str, token: str):
        # hvac is optional
        try:
            import hvac
            self.client = hvac.Client(url=url, token=token)
        except Exception:
            self.client = None
        self.fernet_secret_path = os.getenv('FERNET_SECRET_PATH', 'secret/data/ciai/fernet')

    def get_secret(self, name: str) -> Optional[str]:
        if not self.client:
            return None
        try:
            resp = self.client.secrets.kv.v2.read_secret_version(path=name)
            return resp['data']['data'].get('value')
        except Exception:
            return None

    def put_secret(self, name: str, value: str) -> None:
        if not self.client:
            return
        try:
            self.client.secrets.kv.v2.create_or_update_secret(path=name, secret={'value': value})
        except Exception:
            pass

    def get_fernet_key(self) -> bytes:
        if not self.client:
            return self.rotate_fernet_key()
        try:
            resp = self.client.secrets.kv.v2.read_secret_version(path=self.fernet_secret_path)
            key = resp['data']['data'].get('key')
            if key:
                return key.encode('utf-8')
        except Exception:
            pass
        return self.rotate_fernet_key()

    def rotate_fernet_key(self) -> bytes:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        if self.client:
            try:
                self.client.secrets.kv.v2.create_or_update_secret(path=self.fernet_secret_path, secret={'key': key.decode('utf-8')})
            except Exception:
                pass
        return key


class LocalFernetManager(BaseSecretsManager):
    backend_name = "local"

    def __init__(self):
        # store key in file for development
        self.path = os.getenv('FERNET_KEY_FILE', '/tmp/ciai_fernet.key')

    def get_secret(self, name: str) -> Optional[str]:
        return None

    def put_secret(self, name: str, value: str) -> None:
        return None

    def get_fernet_key(self) -> bytes:
        if os.path.exists(self.path):
            with open(self.path, 'rb') as f:
                return f.read().strip()
        return self.rotate_fernet_key()

    def rotate_fernet_key(self) -> bytes:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        try:
            with open(self.path, 'wb') as f:
                f.write(key)
        except Exception:
            pass
        return key


def get_secrets_manager() -> BaseSecretsManager:
    # Priority: AWS KMS/Secrets Manager -> Vault -> Local
    managed_required = os.getenv('SECRETS_MODE', 'optional').lower() == 'managed_required'

    kms_key = os.getenv('KMS_KEY_ID')
    if kms_key:
        try:
            return KMSSecretsManager(kms_key)
        except Exception:
            pass

    vault_url = os.getenv('VAULT_URL')
    vault_token = os.getenv('VAULT_TOKEN')
    if vault_url and vault_token:
        try:
            return VaultSecretsManager(vault_url, vault_token)
        except Exception:
            pass

    if managed_required:
        raise RuntimeError(
            "SECRETS_MODE=managed_required but no managed backend is configured. "
            "Set KMS_KEY_ID (AWS) or VAULT_URL/VAULT_TOKEN (Vault)."
        )

    return LocalFernetManager()
