"""Simple OIDC test provider serving a JWKS and token generation endpoint.

Run with: python scripts/oidc_test_provider.py
"""
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import uvicorn
from typing import List
import json
import datetime
import os

from jwt import encode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

APP_PORT = int(os.getenv('OIDC_TEST_PORT', '9000'))

app = FastAPI(title='CIAI OIDC Test Provider')

# Generate an RSA keypair on startup
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
PUBLIC_KEY = KEY.public_key()
PUBLIC_PEM = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Build a minimal JWKS
def _jwk_from_public_key(pub_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    numbers = pub_key.public_numbers()
    e = numbers.e
    n = numbers.n
    # Use simple base64url encoding
    import base64
    def b64u(x: int) -> str:
        b = x.to_bytes((x.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode('ascii')

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key-1",
        "n": b64u(n),
        "e": b64u(e),
    }


@app.get('/.well-known/openid-configuration')
def openid_config():
    issuer = f"http://localhost:{APP_PORT}"
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
    }


@app.get('/.well-known/jwks.json')
def jwks():
    jwk = _jwk_from_public_key(PUBLIC_KEY)
    return JSONResponse({"keys": [jwk]})


@app.post('/token')
def token(iss: str = Query('test-issuer'), sub: str = Query('user:1'), aud: str = Query('ciai'), tenant: str = Query(None), groups: str = Query(None)):
    now = datetime.datetime.utcnow()
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
    }
    if tenant:
        payload['tenant'] = tenant
    if groups:
        payload['groups'] = groups.split(',')

    token = encode(payload, PRIVATE_PEM, algorithm='RS256', headers={"kid": "test-key-1"})
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=APP_PORT)
