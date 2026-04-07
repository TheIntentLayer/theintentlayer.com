"""SQLite database initialization and access."""

import os
import secrets
import sqlite3
from contextlib import contextmanager

from app.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    google_id TEXT UNIQUE,
    github_id TEXT UNIQUE,
    github_owner TEXT,
    github_repo TEXT,
    github_pat TEXT,
    github_branch TEXT DEFAULT 'main',
    az_org TEXT,
    az_project TEXT,
    az_pat TEXT,
    api_key TEXT UNIQUE NOT NULL,
    setup_complete INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
    response_types TEXT NOT NULL DEFAULT '["code"]',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


def generate_api_key() -> str:
    """Generate a new API key with aicc- prefix."""
    return f"aicc-{secrets.token_hex(32)}"


def init_db():
    """Create tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with get_db() as db:
        db.executescript(SCHEMA)


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_user(name: str, email: str, password_hash: str | None = None) -> dict:
    """Create a new user. Returns the user row as a dict."""
    api_key = generate_api_key()
    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO users (name, email, password_hash, api_key)
               VALUES (?, ?, ?, ?)""",
            (name, email, password_hash, api_key),
        )
        row = db.execute(
            "SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return dict(row)


def get_user_by_email(email: str) -> dict | None:
    """Look up a user by email."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    """Look up a user by ID."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_api_key(api_key: str) -> dict | None:
    """Look up an active user by API key."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE api_key = ? AND active = 1", (api_key,)
        ).fetchone()
        return dict(row) if row else None


def update_user_config(
    user_id: int,
    github_owner: str,
    github_repo: str,
    github_pat: str,
    github_branch: str = "main",
    az_org: str | None = None,
    az_project: str | None = None,
    az_pat: str | None = None,
) -> None:
    """Update a user's configuration and mark setup as complete."""
    with get_db() as db:
        db.execute(
            """UPDATE users SET
                github_owner = ?, github_repo = ?, github_pat = ?,
                github_branch = ?, az_org = ?, az_project = ?, az_pat = ?,
                setup_complete = 1
               WHERE id = ?""",
            (github_owner, github_repo, github_pat, github_branch,
             az_org, az_project, az_pat, user_id),
        )
