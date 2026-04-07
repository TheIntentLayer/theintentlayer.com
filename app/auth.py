"""Password hashing and session management."""

from datetime import datetime, timezone

import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.config import WEB_SECRET_KEY
from app.db import get_db

_serializer = URLSafeTimedSerializer(WEB_SECRET_KEY)
SESSION_COOKIE_NAME = "til_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_session_token(account_id: int) -> str:
    return _serializer.dumps({"account_id": account_id})


def validate_session_token(token: str) -> dict | None:
    """Returns {"account_id": int} or None if invalid/expired."""
    try:
        return _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def create_account(name: str, email: str, password: str) -> int:
    """Create a new account. Returns account ID. Raises if email taken."""
    pw_hash = hash_password(password)
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO accounts (email, password_hash, name) VALUES (?, ?, ?)",
            (email, pw_hash, name),
        )
        return cursor.lastrowid


def authenticate(email: str, password: str) -> dict | None:
    """Verify credentials. Returns account row or None."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM accounts WHERE email = ?", (email,)
        ).fetchone()
        if row and verify_password(password, row["password_hash"]):
            db.execute(
                "UPDATE accounts SET last_login = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"]),
            )
            return dict(row)
    return None


def get_account_by_id(account_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        return dict(row) if row else None
