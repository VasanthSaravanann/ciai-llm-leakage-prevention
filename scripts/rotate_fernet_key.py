#!/usr/bin/env python3
"""Rotate Fernet key via configured secrets manager.

Usage:
    python scripts/rotate_fernet_key.py

This will create a new Fernet key and persist it using the preferred secrets
manager (KMS/Secrets Manager, Vault, or local file).
"""
from src.secrets.manager import get_secrets_manager

mgr = get_secrets_manager()
new_key = mgr.rotate_fernet_key()
print("New Fernet key generated and stored.")
