"""Tests for registration and login flows."""

import os
import tempfile

import pytest

# Use temp DB and disable secure cookies for tests
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DB_PATH"] = _tmp.name
os.environ["COOKIE_SECURE"] = "false"
_tmp.close()

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


client = TestClient(app)


def test_landing_page():
    r = client.get("/")
    assert r.status_code == 200
    assert "The Intent Layer" in r.text


def test_register_page():
    r = client.get("/auth/register")
    assert r.status_code == 200
    assert "Create Account" in r.text


def test_register_and_login():
    # Register
    r = client.post(
        "/auth/register",
        data={"name": "Test User", "email": "test@example.com", "password": "testpass123"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/auth/login" in r.headers["location"]

    # Login
    r = client.post(
        "/auth/login",
        data={"email": "test@example.com", "password": "testpass123"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/dashboard" in r.headers["location"]


def test_register_duplicate_email():
    client.post(
        "/auth/register",
        data={"name": "User 1", "email": "dup@example.com", "password": "testpass123"},
    )
    r = client.post(
        "/auth/register",
        data={"name": "User 2", "email": "dup@example.com", "password": "testpass456"},
    )
    assert r.status_code == 200
    assert "already exists" in r.text


def test_register_short_password():
    r = client.post(
        "/auth/register",
        data={"name": "User", "email": "short@example.com", "password": "short"},
    )
    assert r.status_code == 200
    assert "at least 8" in r.text


def test_login_wrong_password():
    client.post(
        "/auth/register",
        data={"name": "User", "email": "wrong@example.com", "password": "testpass123"},
    )
    r = client.post(
        "/auth/login",
        data={"email": "wrong@example.com", "password": "badpassword"},
    )
    assert r.status_code == 200
    assert "Invalid" in r.text


def test_dashboard_requires_login():
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 302
    assert "/auth/login" in r.headers["location"]
