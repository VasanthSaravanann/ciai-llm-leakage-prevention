from typing import Any
import os
from fastapi import Request, HTTPException
from starlette.status import HTTP_403_FORBIDDEN
from jose import JWTError, jwt

from src.config import settings, get_api_keys


def _get_bearer_token(request: Request) -> str | None:
    auth = request.headers.get('Authorization')
    if not auth:
        return None
    if auth.startswith('Bearer '):
        return auth.split(' ', 1)[1]
    return None


def get_roles_from_token(token: str) -> list[str]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return []
    claim = getattr(settings, 'ROLE_CLAIM', 'groups')
    roles = payload.get(claim, [])
    if isinstance(roles, str):
        # single role string
        return [roles]
    if isinstance(roles, (list, tuple)):
        return list(roles)
    return []


def ensure_admin(request: Request) -> None:
    """Raise HTTPException unless caller is admin.

    Behavior:
    - If ADMIN_AUTH_REQUIRED is False, allow through.
    - If X-API-KEY equals ADMIN_API_KEY, allow.
    - If Authorization Bearer JWT contains role claim with 'admin', allow.
    - Otherwise raise 403.
    """
    if not settings.ADMIN_AUTH_REQUIRED:
        return

    # Check admin API key first
    api_key = request.headers.get(settings.API_KEY_NAME)
    if api_key and settings.ADMIN_API_KEY and api_key == settings.ADMIN_API_KEY:
        return

    # Support bearer JWT with role claim
    token = _get_bearer_token(request)
    if token:
        roles = get_roles_from_token(token)
        if 'admin' in roles or 'Administrator' in roles:
            return

    # Not authorized as admin
    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Admin privileges required")


def get_tenant_from_request(request: Request) -> str | None:
    """Extract tenant identifier from request.

    Order of resolution:
    1. X-Tenant-ID header
    2. 'tenant' or 'org' claim inside Bearer JWT
    3. None
    """
    # 1. Header
    tenant = request.headers.get('X-Tenant-ID')
    if tenant:
        return tenant

    # 2. JWT
    token = _get_bearer_token(request)
    if token:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            for claim in ('tenant', 'org', 'organization'):
                if claim in payload:
                    return payload.get(claim)
        except JWTError:
            return None

    return None
