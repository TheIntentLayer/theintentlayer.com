"""OAuth 2.1 endpoint logic."""

import hashlib
import base64
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse

from app.auth import (
    validate_session_token,
    authenticate,
    create_session_token,
    SESSION_COOKIE_NAME,
)
from app.config import (
    ISSUER,
    MCP_RESOURCE,
    AUTH_CODE_LIFETIME_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    REFRESH_TOKEN_LIFETIME_DAYS,
    SUPPORTED_SCOPES,
    COOKIE_SECURE,
)
from app.db import get_db, get_user_by_id
from app.jwt_utils import create_access_token

router = APIRouter()


# ---------------------------------------------------------------------------
# Well-known endpoints
# ---------------------------------------------------------------------------

@router.get("/.well-known/oauth-protected-resource")
async def protected_resource():
    return JSONResponse({
        "resource": MCP_RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": SUPPORTED_SCOPES,
    })


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return JSONResponse({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "registration_endpoint": f"{ISSUER}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": ["none"],
    })


# ---------------------------------------------------------------------------
# Dynamic client registration
# ---------------------------------------------------------------------------

@router.post("/oauth/register")
async def register_client(request: Request):
    body = await request.json()
    client_name = body.get("client_name", "Unknown Client")
    redirect_uris = body.get("redirect_uris", [])
    grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
    response_types = body.get("response_types", ["code"])

    if not redirect_uris:
        raise HTTPException(400, "redirect_uris required")

    client_id = str(uuid.uuid4())

    with get_db() as db:
        db.execute(
            """INSERT INTO oauth_clients
               (client_id, client_name, redirect_uris, grant_types, response_types)
               VALUES (?, ?, ?, ?, ?)""",
            (
                client_id,
                client_name,
                json.dumps(redirect_uris),
                json.dumps(grant_types),
                json.dumps(response_types),
            ),
        )

    return JSONResponse(
        {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

def _get_current_user(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = validate_session_token(token)
    if not session:
        return None
    return get_user_by_id(session["user_id"])


@router.get("/oauth/authorize")
async def authorize_get(request: Request):
    client_id = request.query_params.get("client_id", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    response_type = request.query_params.get("response_type", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")
    scope = request.query_params.get("scope", "mcp:tools mcp:resources")
    state = request.query_params.get("state", "")

    # Validate required params
    if response_type != "code":
        raise HTTPException(400, "response_type must be 'code'")
    if not code_challenge:
        raise HTTPException(400, "code_challenge required (PKCE)")

    # Look up client
    with get_db() as db:
        client = db.execute(
            "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()

    if not client:
        raise HTTPException(400, "Unknown client_id")

    allowed_uris = json.loads(client["redirect_uris"])
    if redirect_uri not in allowed_uris:
        raise HTTPException(400, "redirect_uri not registered")

    user = _get_current_user(request)

    templates = request.app.state.templates

    if not user:
        # Show login form with oauth params preserved
        return templates.TemplateResponse(
            "authorize.html",
            {
                "request": request,
                "client_name": client["client_name"],
                "scope": scope,
                "show_login": True,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "state": state,
                "error": None,
            },
        )

    # User is logged in -- show consent screen
    return templates.TemplateResponse(
        "authorize.html",
        {
            "request": request,
            "client_name": client["client_name"],
            "scope": scope,
            "show_login": False,
            "user": user,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "error": None,
        },
    )


@router.post("/oauth/authorize")
async def authorize_post(
    request: Request,
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    response_type: str = Form("code"),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
    scope: str = Form("mcp:tools mcp:resources"),
    state: str = Form(""),
    action: str = Form(""),
    # Login fields (when not yet authenticated)
    email: str = Form(""),
    password: str = Form(""),
):
    templates = request.app.state.templates

    # Look up client
    with get_db() as db:
        client = db.execute(
            "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()

    if not client:
        raise HTTPException(400, "Unknown client_id")

    user = _get_current_user(request)

    # If not logged in, try to authenticate
    if not user:
        if not email or not password:
            return templates.TemplateResponse(
                "authorize.html",
                {
                    "request": request,
                    "client_name": client["client_name"],
                    "scope": scope,
                    "show_login": True,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "response_type": response_type,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "state": state,
                    "error": "Email and password required.",
                },
            )

        user = authenticate(email, password)
        if not user:
            return templates.TemplateResponse(
                "authorize.html",
                {
                    "request": request,
                    "client_name": client["client_name"],
                    "scope": scope,
                    "show_login": True,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "response_type": response_type,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "state": state,
                    "error": "Invalid email or password.",
                },
            )

        # Set session cookie so they stay logged in
        session_token = create_session_token(user["id"])

        # After login, show consent screen
        response = templates.TemplateResponse(
            "authorize.html",
            {
                "request": request,
                "client_name": client["client_name"],
                "scope": scope,
                "show_login": False,
                "user": user,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "state": state,
                "error": None,
            },
        )
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response

    # User is authenticated and making a decision
    if action == "deny":
        params = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(f"{redirect_uri}?{params}", status_code=302)

    # action == "approve" -- generate auth code
    code = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=AUTH_CODE_LIFETIME_SECONDS)

    with get_db() as db:
        db.execute(
            """INSERT INTO oauth_codes
               (code, client_id, user_id, redirect_uri, scope,
                code_challenge, code_challenge_method, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                code,
                client_id,
                user["id"],
                redirect_uri,
                scope,
                code_challenge,
                code_challenge_method,
                expires_at.isoformat(),
            ),
        )

    params = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{params}", status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify S256 PKCE: BASE64URL(SHA256(code_verifier)) == code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


@router.post("/oauth/token")
async def token_endpoint(
    grant_type: str = Form(""),
    code: str = Form(""),
    code_verifier: str = Form(""),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    refresh_token: str = Form(""),
    resource: str = Form(""),
):
    if grant_type == "authorization_code":
        return _handle_auth_code(code, code_verifier, client_id, redirect_uri)
    elif grant_type == "refresh_token":
        return _handle_refresh(refresh_token, client_id)
    else:
        raise HTTPException(400, "unsupported grant_type")


def _handle_auth_code(
    code: str, code_verifier: str, client_id: str, redirect_uri: str
):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM oauth_codes WHERE code = ?", (code,)
        ).fetchone()

        if not row:
            raise HTTPException(400, "invalid authorization code")

        if row["used"]:
            raise HTTPException(400, "authorization code already used")

        expires_at = datetime.fromisoformat(row["expires_at"]).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            raise HTTPException(400, "authorization code expired")

        if row["client_id"] != client_id:
            raise HTTPException(400, "client_id mismatch")

        if row["redirect_uri"] != redirect_uri:
            raise HTTPException(400, "redirect_uri mismatch")

        # PKCE validation
        if not _verify_pkce(code_verifier, row["code_challenge"]):
            raise HTTPException(400, "PKCE verification failed")

        # Mark code as used
        db.execute("UPDATE oauth_codes SET used = 1 WHERE code = ?", (code,))

        # Generate tokens
        user_id = row["user_id"]
        scope = row["scope"]

        access_token, access_expires = create_access_token(user_id, scope)
        refresh_tok = secrets.token_urlsafe(48)
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=REFRESH_TOKEN_LIFETIME_DAYS
        )

        # Store access token reference
        db.execute(
            """INSERT INTO oauth_tokens
               (token, client_id, user_id, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (access_token, client_id, user_id, scope, access_expires.isoformat()),
        )

        # Store refresh token
        db.execute(
            """INSERT INTO oauth_refresh_tokens
               (token, client_id, user_id, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (refresh_tok, client_id, user_id, scope, refresh_expires.isoformat()),
        )

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
        "refresh_token": refresh_tok,
    })


def _handle_refresh(refresh_token: str, client_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM oauth_refresh_tokens WHERE token = ?",
            (refresh_token,),
        ).fetchone()

        if not row:
            raise HTTPException(400, "invalid refresh token")

        expires_at = datetime.fromisoformat(row["expires_at"]).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            raise HTTPException(400, "refresh token expired")

        if row["client_id"] != client_id:
            raise HTTPException(400, "client_id mismatch")

        # Rotate: delete old refresh token, issue new ones
        user_id = row["user_id"]
        scope = row["scope"]

        db.execute(
            "DELETE FROM oauth_refresh_tokens WHERE token = ?", (refresh_token,)
        )

        access_token, access_expires = create_access_token(user_id, scope)
        new_refresh = secrets.token_urlsafe(48)
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=REFRESH_TOKEN_LIFETIME_DAYS
        )

        db.execute(
            """INSERT INTO oauth_tokens
               (token, client_id, user_id, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (access_token, client_id, user_id, scope, access_expires.isoformat()),
        )

        db.execute(
            """INSERT INTO oauth_refresh_tokens
               (token, client_id, user_id, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (new_refresh, client_id, user_id, scope, refresh_expires.isoformat()),
        )

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
        "refresh_token": new_refresh,
    })
