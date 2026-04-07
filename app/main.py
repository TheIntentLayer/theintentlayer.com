"""FastAPI application for theintentlayer.com."""

import re
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import init_db, get_db, get_user_by_id, update_user_config
from app.auth import (
    register_user,
    authenticate,
    create_session_token,
    validate_session_token,
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

def _current_user(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = validate_session_token(token)
    if not session:
        return None
    return get_user_by_id(session["user_id"])


def _parse_github_url(url: str) -> tuple[str, str] | None:
    """Extract owner and repo from a GitHub URL or shorthand.
    Accepts: github.com/owner/repo, https://github.com/owner/repo,
    https://github.com/owner/repo.git, owner/repo
    """
    url = url.strip().rstrip("/")
    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]
    # Try to match github.com/owner/repo pattern
    match = re.search(r"github\.com/([^/]+)/([^/]+)$", url)
    if match:
        return match.group(1), match.group(2)
    # Try owner/repo pattern (no dots, no slashes beyond one)
    match = re.match(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$", url)
    if match:
        return match.group(1), match.group(2)
    return None


# ---------------------------------------------------------------------------
# Landing page (excitement page)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = _current_user(request)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
    })


# ---------------------------------------------------------------------------
# Product page (technical details)
# ---------------------------------------------------------------------------

@app.get("/product", response_class=HTMLResponse)
async def product(request: Request):
    user = _current_user(request)
    return templates.TemplateResponse("product.html", {
        "request": request,
        "user": user,
    })


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
        user = register_user(name, email, password)
    except sqlite3.IntegrityError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "An account with that email already exists."},
        )

    # Auto-login after registration
    session_token = create_session_token(user["id"])
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
    next_url = request.query_params.get("next", "/dashboard")
    user = authenticate(email, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password.", "success": None},
        )

    session_token = create_session_token(user["id"])
    response = RedirectResponse(next_url, status_code=302)
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
    user = _current_user(request)
    if not user:
        return RedirectResponse("/auth/login?next=/dashboard", status_code=302)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
        },
    )


@app.post("/dashboard/setup", response_class=HTMLResponse)
async def dashboard_setup(
    request: Request,
    github_repo_url: str = Form(""),
    github_pat: str = Form(""),
    az_org: str = Form(""),
    az_project: str = Form(""),
    az_pat: str = Form(""),
):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/auth/login", status_code=302)

    errors = []
    if not github_repo_url:
        errors.append("GitHub repo URL is required.")
    if not github_pat:
        errors.append("GitHub PAT is required.")

    parsed = _parse_github_url(github_repo_url) if github_repo_url else None
    if github_repo_url and not parsed:
        errors.append("Could not parse GitHub repo URL. Use format: github.com/owner/repo")

    if errors:
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "error": " ".join(errors),
            },
        )

    owner, repo = parsed
    update_user_config(
        user_id=user["id"],
        github_owner=owner,
        github_repo=repo,
        github_pat=github_pat,
        az_org=az_org or None,
        az_project=az_project or None,
        az_pat=az_pat or None,
    )

    return RedirectResponse("/dashboard", status_code=302)


@app.post("/dashboard/update", response_class=HTMLResponse)
async def dashboard_update(
    request: Request,
    github_repo_url: str = Form(""),
    github_pat: str = Form(""),
    az_org: str = Form(""),
    az_project: str = Form(""),
    az_pat: str = Form(""),
):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/auth/login", status_code=302)

    parsed = _parse_github_url(github_repo_url) if github_repo_url else None
    if github_repo_url and not parsed:
        # Refresh user to get current data
        user = get_user_by_id(user["id"])
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "error": "Could not parse GitHub repo URL.",
                "editing": True,
            },
        )

    if parsed:
        owner, repo = parsed
    else:
        owner = user.get("github_owner")
        repo = user.get("github_repo")

    update_user_config(
        user_id=user["id"],
        github_owner=owner,
        github_repo=repo,
        github_pat=github_pat or user.get("github_pat"),
        az_org=az_org or None,
        az_project=az_project or None,
        az_pat=az_pat or None,
    )

    return RedirectResponse("/dashboard", status_code=302)
