from __future__ import annotations

import json
import time
from typing import Any

import requests
from fastapi import HTTPException, Request
from jose import JWTError, jwt
from starlette.status import HTTP_403_FORBIDDEN

from src.config import get_api_keys, settings

# In-memory cache for OIDC JWKS keys.
_JWKS_CACHE: dict[str, Any] = {"expires_at": 0, "keys": []}

# Internal RBAC permissions.
_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"admin", "view_metrics", "view_dashboard", "view_audit", "manage_policy", "manage_keys"},
    "view_audit": {"view_dashboard", "view_audit"},
    "view_metrics": {"view_metrics"},
    "manage_policy": {"manage_policy"},
    "manage_keys": {"manage_keys"},
}


def _get_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _get_group_map() -> dict[str, str]:
    try:
        raw = getattr(settings, "RBAC_GROUP_MAP_JSON", "{}")
        parsed = json.loads(raw) if raw else {}
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    except Exception:
        pass
    return {}


def _extract_roles(payload: dict[str, Any]) -> list[str]:
    claim = getattr(settings, "ROLE_CLAIM", "groups")
    raw_roles = payload.get(claim, [])
    roles: list[str]
    if isinstance(raw_roles, str):
        roles = [raw_roles]
    elif isinstance(raw_roles, (list, tuple)):
        roles = [str(r) for r in raw_roles]
    else:
        roles = []

    group_map = _get_group_map()
    mapped_roles = [group_map.get(r, r) for r in roles]
    return list({r for r in mapped_roles if r})


def _permissions_for_roles(roles: list[str]) -> set[str]:
    permissions: set[str] = set()
    for role in roles:
        permissions.update(_ROLE_PERMISSIONS.get(role, set()))
    return permissions


def _decode_shared_secret_jwt(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def _get_jwks_keys() -> list[dict[str, Any]]:
    now = time.time()
    if _JWKS_CACHE["keys"] and now < float(_JWKS_CACHE["expires_at"]):
        return _JWKS_CACHE["keys"]

    url = settings.OIDC_JWKS_URL
    if not url:
        issuer = settings.OIDC_ISSUER.rstrip("/")
        if issuer:
            url = f"{issuer}/.well-known/jwks.json"

    if not url:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="OIDC JWKS URL not configured")

    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    body = resp.json()
    keys = body.get("keys", []) if isinstance(body, dict) else []
    if not isinstance(keys, list):
        keys = []

    ttl = max(30, int(getattr(settings, "OIDC_JWKS_TTL_SECONDS", 300)))
    _JWKS_CACHE["keys"] = keys
    _JWKS_CACHE["expires_at"] = now + ttl
    return keys


def _decode_oidc_jwt(token: str) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    keys = _get_jwks_keys()
    key = next((k for k in keys if k.get("kid") == kid), None)
    if not key:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="OIDC key id not found")

    kwargs: dict[str, Any] = {
        "algorithms": [header.get("alg", settings.JWT_ALGORITHM)],
    }
    if settings.OIDC_ISSUER:
        kwargs["issuer"] = settings.OIDC_ISSUER
    if settings.OIDC_AUDIENCE:
        kwargs["audience"] = settings.OIDC_AUDIENCE

    return jwt.decode(token, key, **kwargs)


def authenticate_request(request: Request) -> dict[str, Any]:
    """Authenticate caller via API key or JWT/OIDC and return identity context."""
    api_key = request.headers.get(settings.API_KEY_NAME)
    if api_key and api_key in get_api_keys():
        return {
            "auth_type": "api_key",
            "subject": "api-key",
            "roles": [],
            "permissions": set(),
            "token_payload": {},
            "tenant_id": request.headers.get("X-Tenant-ID"),
        }

    token = _get_bearer_token(request)
    if token:
        payload: dict[str, Any]
        try:
            if settings.OIDC_ENABLED:
                payload = _decode_oidc_jwt(token)
            else:
                payload = _decode_shared_secret_jwt(token)
        except Exception as exc:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid bearer token") from exc

        roles = _extract_roles(payload)
        permissions = _permissions_for_roles(roles)
        tenant_id = request.headers.get("X-Tenant-ID")
        if not tenant_id:
            for claim in ("tenant_id", "tenant", "org", "organization"):
                if payload.get(claim):
                    tenant_id = str(payload.get(claim))
                    break

        return {
            "auth_type": "oidc_jwt" if settings.OIDC_ENABLED else "jwt",
            "subject": payload.get("sub", "jwt-user"),
            "roles": roles,
            "permissions": permissions,
            "token_payload": payload,
            "tenant_id": tenant_id,
        }

    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid or missing API key / token")


def ensure_permission(request: Request, permission: str) -> None:
    """Raise unless caller is authorized for the specified permission."""
    if not settings.ADMIN_AUTH_REQUIRED:
        return

    # Machine-level admin key bypass for controlled automation.
    api_key = request.headers.get(settings.API_KEY_NAME)
    if api_key and settings.ADMIN_API_KEY and api_key == settings.ADMIN_API_KEY:
        return

    ctx = authenticate_request(request)
    perms = ctx.get("permissions", set())
    if "admin" in perms or permission in perms:
        return
    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient RBAC permission")


def ensure_admin(request: Request) -> None:
    ensure_permission(request, "admin")


def get_tenant_from_request(request: Request) -> str | None:
    """Extract tenant identifier from X-Tenant-ID or JWT/OIDC claims."""
    tenant = request.headers.get("X-Tenant-ID")
    if tenant:
        return tenant

    token = _get_bearer_token(request)
    if not token:
        return None

    try:
        payload = _decode_oidc_jwt(token) if settings.OIDC_ENABLED else _decode_shared_secret_jwt(token)
        for claim in ("tenant_id", "tenant", "org", "organization"):
            if payload.get(claim):
                return str(payload.get(claim))
    except Exception:
        return None

    return None


def require_tenant(request: Request) -> str:
    tenant = get_tenant_from_request(request)
    if settings.TENANT_ISOLATION_REQUIRED and not tenant:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Tenant context required")
    return tenant or ""
