"""FastAPI application for theintentlayer.com."""

import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import init_db
from app.auth import (
    create_account,
    authenticate,
    create_session_token,
    validate_session_token,
    get_account_by_id,
    SESSION_COOKIE_NAME,
)
from app.config import COOKIE_SECURE
from app.oauth import router as oauth_router

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="The Intent Layer", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=BASE_DIR / "templates")
app.state.templates = templates


@app.on_event("startup")
async def startup():
    init_db()


# Include OAuth routes
app.include_router(oauth_router)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_account(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = validate_session_token(token)
    if not session:
        return None
    return get_account_by_id(session["account_id"])


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ---------------------------------------------------------------------------
# Auth: Register
# ---------------------------------------------------------------------------

@app.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html", {"request": request, "error": None}
    )


@app.post("/auth/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
):
    if not name or not email or not password:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "All fields are required."},
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password must be at least 8 characters."},
        )
    try:
        create_account(name, email, password)
    except sqlite3.IntegrityError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "An account with that email already exists."},
        )
    return RedirectResponse("/auth/login?registered=1", status_code=302)


# ---------------------------------------------------------------------------
# Auth: Login
# ---------------------------------------------------------------------------

@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request):
    registered = request.query_params.get("registered")
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "success": "Account created. Please log in." if registered else None,
        },
    )


@app.post("/auth/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
):
    account = authenticate(email, password)
    if not account:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password.", "success": None},
        )

    session_token = create_session_token(account["id"])
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=86400 * 7,
    )
    return response


# ---------------------------------------------------------------------------
# Auth: Logout
# ---------------------------------------------------------------------------

@app.get("/auth/logout")
async def logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    account = _current_account(request)
    if not account:
        return RedirectResponse("/auth/login", status_code=302)

    # Get linked API keys
    from app.db import get_db

    with get_db() as db:
        keys = db.execute(
            "SELECT api_key FROM account_api_keys WHERE account_id = ?",
            (account["id"],),
        ).fetchall()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "account": account,
            "api_keys": [k["api_key"] for k in keys],
        },
    )
