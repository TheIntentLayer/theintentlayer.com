"""JWT creation and validation for OAuth tokens."""

import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.config import (
    JWT_SECRET,
    ISSUER,
    MCP_RESOURCE,
    ACCESS_TOKEN_LIFETIME_SECONDS,
)


def create_access_token(account_id: int, scope: str) -> tuple[str, datetime]:
    """Create a signed JWT access token. Returns (token, expires_at)."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ACCESS_TOKEN_LIFETIME_SECONDS)
    payload = {
        "iss": ISSUER,
        "sub": str(account_id),
        "aud": MCP_RESOURCE,
        "scope": scope,
        "exp": expires_at,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token, expires_at


def validate_access_token(token: str) -> dict | None:
    """Decode and validate a JWT. Returns payload or None."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=MCP_RESOURCE,
            issuer=ISSUER,
        )
        return payload
    except jwt.PyJWTError:
        return None
