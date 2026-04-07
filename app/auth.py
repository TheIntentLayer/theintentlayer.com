"""Password hashing and session management."""

from datetime import datetime, timezone

import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.config import WEB_SECRET_KEY
from app.db import get_db, create_user, get_user_by_email, get_user_by_id

_serializer = URLSafeTimedSerializer(WEB_SECRET_KEY)
SESSION_COOKIE_NAME = "til_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_session_token(user_id: int) -> str:
    return _serializer.dumps({"user_id": user_id})


def validate_session_token(token: str) -> dict | None:
    """Returns {"user_id": int} or None if invalid/expired."""
    try:
        return _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def register_user(name: str, email: str, password: str) -> dict:
    """Create a new user with hashed password. Returns user dict.
    Raises sqlite3.IntegrityError if email taken."""
    pw_hash = hash_password(password)
    return create_user(name, email, password_hash=pw_hash)


def authenticate(email: str, password: str) -> dict | None:
    """Verify credentials. Returns user row or None."""
    user = get_user_by_email(email)
    if user and user["password_hash"] and verify_password(password, user["password_hash"]):
        with get_db() as db:
            db.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), user["id"]),
            )
        return user
    return None
