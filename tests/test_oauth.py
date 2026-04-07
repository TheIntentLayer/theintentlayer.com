"""Tests for OAuth 2.1 flow."""

import base64
import hashlib
import os
import secrets
import tempfile
from urllib.parse import urlparse, parse_qs

import pytest

# Use temp DB and disable secure cookies for tests
if "DB_PATH" not in os.environ:
    _tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    os.environ["DB_PATH"] = _tmp.name
    _tmp.close()
os.environ["COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    yield
    import sqlite3
    conn = sqlite3.connect(os.environ["DB_PATH"])
    for table in ["accounts", "account_api_keys", "oauth_clients", "oauth_codes", "oauth_tokens", "oauth_refresh_tokens"]:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()


def _make_client():
    """Create a TestClient with cookie persistence."""
    return TestClient(app, cookies={})


def _register_and_login(c: TestClient):
    """Helper: create account and login via the test client (cookies persist)."""
    c.post(
        "/auth/register",
        data={"name": "OAuth User", "email": "oauth@example.com", "password": "testpass123"},
    )
    c.post(
        "/auth/login",
        data={"email": "oauth@example.com", "password": "testpass123"},
        follow_redirects=False,
    )


def _register_oauth_client(c: TestClient):
    """Helper: dynamically register an OAuth client."""
    r = c.post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert r.status_code == 201
    return r.json()


def _make_pkce():
    """Generate PKCE code_verifier and code_challenge."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def test_well_known_protected_resource():
    c = _make_client()
    r = c.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    data = r.json()
    assert data["resource"] == "https://mcp.theintentlayer.com/mcp"
    assert "mcp:tools" in data["scopes_supported"]


def test_well_known_authorization_server():
    c = _make_client()
    r = c.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    data = r.json()
    assert data["issuer"] == "https://theintentlayer.com"
    assert "S256" in data["code_challenge_methods_supported"]
    assert data["registration_endpoint"] == "https://theintentlayer.com/oauth/register"


def test_dynamic_client_registration():
    c = _make_client()
    data = _register_oauth_client(c)
    assert "client_id" in data
    assert data["client_name"] == "Claude"
    assert "https://claude.ai/api/mcp/auth_callback" in data["redirect_uris"]


def test_authorize_requires_login():
    c = _make_client()
    oauth_client = _register_oauth_client(c)
    _, challenge = _make_pkce()

    r = c.get(
        "/oauth/authorize",
        params={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "test-state",
        },
    )
    assert r.status_code == 200
    assert "Log In" in r.text


def test_full_oauth_flow():
    """Test the complete OAuth 2.1 authorization code flow with PKCE."""
    c = _make_client()
    oauth_client = _register_oauth_client(c)
    verifier, challenge = _make_pkce()

    # Register and login (session cookie persists on c)
    _register_and_login(c)

    # GET authorize (should show consent screen)
    r = c.get(
        "/oauth/authorize",
        params={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "test-state-123",
        },
    )
    assert r.status_code == 200
    assert "Approve" in r.text

    # POST approve
    r = c.post(
        "/oauth/authorize",
        data={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "test-state-123",
            "action": "approve",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    location = r.headers["location"]
    assert "claude.ai/api/mcp/auth_callback" in location
    assert "code=" in location
    assert "state=test-state-123" in location

    # Extract code
    code = parse_qs(urlparse(location).query)["code"][0]

    # Exchange code for tokens
    r = c.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        },
    )
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens
    assert tokens["token_type"] == "Bearer"
    assert "refresh_token" in tokens
    assert tokens["expires_in"] == 3600

    # Validate the JWT
    from app.jwt_utils import validate_access_token
    payload = validate_access_token(tokens["access_token"])
    assert payload is not None
    assert payload["iss"] == "https://theintentlayer.com"
    assert payload["aud"] == "https://mcp.theintentlayer.com/mcp"

    # Refresh token
    r = c.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": oauth_client["client_id"],
        },
    )
    assert r.status_code == 200
    new_tokens = r.json()
    assert "access_token" in new_tokens
    assert new_tokens["access_token"] != tokens["access_token"]
    assert "refresh_token" in new_tokens


def test_pkce_wrong_verifier():
    """PKCE must reject wrong code_verifier."""
    c = _make_client()
    oauth_client = _register_oauth_client(c)
    _, challenge = _make_pkce()
    wrong_verifier = secrets.token_urlsafe(48)

    _register_and_login(c)

    r = c.post(
        "/oauth/authorize",
        data={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "s",
            "action": "approve",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]

    r = c.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": wrong_verifier,
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        },
    )
    assert r.status_code == 400
    assert "PKCE" in r.json()["detail"]


def test_code_reuse_rejected():
    """Authorization code must be one-time use."""
    c = _make_client()
    oauth_client = _register_oauth_client(c)
    verifier, challenge = _make_pkce()

    _register_and_login(c)

    r = c.post(
        "/oauth/authorize",
        data={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "s",
            "action": "approve",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": oauth_client["client_id"],
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
    }

    # First use -- should succeed
    r1 = c.post("/oauth/token", data=token_data)
    assert r1.status_code == 200

    # Second use -- should fail
    r2 = c.post("/oauth/token", data=token_data)
    assert r2.status_code == 400
    assert "already used" in r2.json()["detail"]


def test_deny_authorization():
    """Deny should redirect with error."""
    c = _make_client()
    oauth_client = _register_oauth_client(c)
    _, challenge = _make_pkce()

    _register_and_login(c)

    r = c.post(
        "/oauth/authorize",
        data={
            "client_id": oauth_client["client_id"],
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools mcp:resources",
            "state": "deny-state",
            "action": "deny",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=access_denied" in r.headers["location"]
