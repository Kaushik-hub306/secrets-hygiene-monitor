"""Secrets Hygiene Monitor - Full backend with OAuth, webhooks, and monitoring."""

import os
import hashlib
import hmac
import json
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional

import requests
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from dotenv import load_dotenv

from api.models import (
    ScanRequest, ScanResponse, ScanResult,
    AlertConfig, HealthResponse,
)
from api.scanner import scan_git_repo
from api.alerts import send_slack_alert, send_discord_alert
from api.security import validate_repo_url
from api.database import (
    init_db, create_user, get_user_by_github, get_user,
    add_repo, get_user_repos, get_repo, get_all_repos,
    delete_repo_db, update_repo_webhook, update_repo_scan_time,
    add_scan, get_scans_for_repo, get_latest_scan,
    set_alert_config, get_alert_config,
)
from api.worker import scan_repo_and_store, run_scheduled_scan

load_dotenv()

# --- Config ---
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
APP_ENV = os.getenv("APP_ENV", "development")
APP_HOST = os.getenv("HOST", "127.0.0.1")
APP_PORT = int(os.getenv("PORT", "8000"))
DISABLE_DOCS = os.getenv("DISABLE_DOCS", "false").lower() == "true"
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", "./data/secrets_monitor.db")
SCAN_INTERVAL_HOURS = int(os.getenv("SCAN_INTERVAL_HOURS", "6"))

app = FastAPI(
    title="Secrets Hygiene Monitor",
    version="0.1.0",
    docs_url="/docs" if not DISABLE_DOCS and APP_ENV != "production" else None,
    redoc_url=None,
)

# Static files and templates
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# --- Session store (use signed cookies in production) ---
_sessions: Dict[str, dict] = {}


def get_session(request: Request) -> Optional[dict]:
    """Get the current user session from cookie."""
    session_id = request.cookies.get("session_id")
    if session_id and session_id in _sessions:
        return _sessions[session_id]
    return None


def require_user(request: Request) -> dict:
    """Require authenticated user or raise 401."""
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session


# --- App startup ---
@app.on_event("startup")
async def startup():
    init_db()
    # Start background scheduler thread
    scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    scheduler_thread.start()
    logger.info(f"Server ready on {APP_HOST}:{APP_PORT}, scheduler started ({SCAN_INTERVAL_HOURS}h interval)")


def _scheduler_loop():
    """Background thread that runs periodic scans."""
    import asyncio
    # Wait a bit for startup
    time.sleep(10)
    while True:
        try:
            asyncio.run(run_scheduled_scan())
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
        # Sleep for the configured interval
        time.sleep(SCAN_INTERVAL_HOURS * 3600)


# --- Rate limiting ---
_rate_limit_store: Dict[str, List[float]] = {}


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.utcnow().timestamp()
    if client_ip in _rate_limit_store:
        _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < 60]
    else:
        _rate_limit_store[client_ip] = []
    if len(_rate_limit_store[client_ip]) >= 60:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rate_limit_store[client_ip].append(now)
    response = await call_next(request)
    return response


# ========== GITHUB OAUTH ==========

@app.get("/auth/github")
async def github_login():
    """Redirect user to GitHub OAuth."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    github_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope=repo,read:user"
        f"&redirect_uri=http://{APP_HOST}:{APP_PORT}/auth/github/callback"
    )
    return RedirectResponse(github_url)


@app.get("/auth/github/callback")
async def github_callback(code: str = Query(...)):
    """Handle GitHub OAuth callback."""
    # Exchange code for access token
    token_resp = requests.post(
        "https://github.com/login/oauth/access_token",
        json={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="GitHub auth failed")

    # Get user info
    user_resp = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {access_token}"},
        timeout=10,
    )
    github_user = user_resp.json()

    # Create or update user in DB
    user_id = create_user(
        github_id=github_user["id"],
        login=github_user["login"],
        email=github_user.get("email", ""),
        access_token=access_token,
    )

    # Set session cookie
    import secrets
    session_id = secrets.token_hex(32)
    _sessions[session_id] = {"user_id": user_id, "login": github_user["login"]}

    resp = RedirectResponse(url="/")
    resp.set_cookie("session_id", session_id, httponly=True, max_age=86400 * 7)
    return resp


@app.get("/auth/logout")
async def logout():
    resp = RedirectResponse(url="/")
    resp.delete_cookie("session_id")
    return resp


@app.get("/auth/me")
async def get_me(request: Request):
    session = get_session(request)
    if not session:
        return {"authenticated": False}
    user = get_user(session["user_id"])
    return {"authenticated": True, "login": session.get("login"), "user_id": session.get("user_id")}


# ========== GITHUB USER REPOS ==========

@app.get("/api/github/repos")
async def list_github_repos(request: Request):
    """List repos from the user's GitHub account."""
    session = require_user(request)
    user = get_user(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    resp = requests.get(
        "https://api.github.com/user/repos?per_page=100&sort=updated",
        headers={"Authorization": f"token {user['access_token']}"},
        timeout=10,
    )
    repos = resp.json()
    return {
        "repos": [
            {
                "id": r["id"],
                "name": r["full_name"],
                "url": r["clone_url"],
                "default_branch": r.get("default_branch", "main"),
                "private": r.get("private", False),
            }
            for r in repos if not r.get("fork")
        ]
    }


# ========== WEBHOOK RECEIVER ==========

@app.post("/webhooks/github")
async def github_webhook(request: Request):
    """Receive GitHub webhook events on push."""
    body = await request.body()

    # Verify signature
    if GITHUB_WEBHOOK_SECRET:
        signature = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid signature")

    event = request.headers.get("X-GitHub-Event", "")

    if event == "ping":
        return {"ok": True}

    if event == "push":
        payload = json.loads(body)
        repo_url = payload.get("repository", {}).get("clone_url", "")
        branch = payload.get("ref", "").replace("refs/heads/", "")

        if not repo_url:
            return {"ok": True}

        # Find all registrations for this repo
        all_repos = get_all_repos()
        for repo in all_repos:
            if repo["url"] == repo_url or repo.get("github_repo_id") == payload.get("repository", {}).get("id"):
                import asyncio
                asyncio.create_task(scan_repo_and_store(
                    repo_id=repo["id"],
                    user_id=repo["user_id"],
                    repo_url=repo["url"],
                    branch=branch,
                    triggered_by="webhook",
                ))

    return {"ok": True}


# ========== API ENDPOINTS ==========

@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.get("/api/dashboard")
async def dashboard_data(request: Request):
    """Get all data for the dashboard."""
    session = get_session(request)
    if not session:
        return {"authenticated": False, "repos": [], "scans": []}

    repos = get_user_repos(session["user_id"])
    scans = []
    for repo in repos:
        latest = get_latest_scan(repo["id"])
        if latest:
            scans.append({
                "repo_name": repo["name"],
                "repo_url": repo["url"],
                **latest,
            })

    return {"authenticated": True, "repos": repos, "scans": scans}


@app.post("/api/repos")
async def add_monitored_repo(request: Request):
    """Add a repo to monitor."""
    session = require_user(request)
    data = await request.json()
    repo_url = data.get("url", "").strip()
    repo_name = data.get("name", "").strip()
    branch = data.get("branch", "main").strip()
    github_repo_id = data.get("github_repo_id")

    if not repo_url:
        raise HTTPException(status_code=400, detail="Missing repo URL")

    url_error = validate_repo_url(repo_url)
    if url_error:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {url_error}")

    if not repo_name:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")

    repo_id = add_repo(
        user_id=session["user_id"],
        name=repo_name,
        url=repo_url,
        branch=branch,
        github_repo_id=github_repo_id,
    )

    return {"repo_id": repo_id, "message": f"Now monitoring '{repo_name}'"}


@app.get("/api/repos")
async def list_monitored_repos(request: Request):
    session = require_user(request)
    repos = get_user_repos(session["user_id"])
    # Add last scan info
    result = []
    for repo in repos:
        latest = get_latest_scan(repo["id"])
        repo_data = {**repo}
        if latest:
            repo_data["last_scan"] = {
                "total_findings": latest["total_findings"],
                "critical": latest["critical"],
                "high": latest["high"],
                "medium": latest["medium"],
                "created_at": latest["created_at"],
            }
        result.append(repo_data)
    return {"repos": result}


@app.post("/api/repos/{repo_id}/scan")
async def trigger_scan(repo_id: str, request: Request):
    """Manually trigger a scan of a monitored repo."""
    session = require_user(request)
    repo = get_repo(repo_id)
    if not repo or repo["user_id"] != session["user_id"]:
        raise HTTPException(status_code=404, detail="Repo not found")

    result = await scan_repo_and_store(
        repo_id=repo["id"],
        user_id=session["user_id"],
        repo_url=repo["url"],
        branch=repo.get("branch", "main"),
        triggered_by="manual",
    )
    return result


@app.post("/api/repos/{repo_id}/alert")
async def configure_alerts(repo_id: str, request: Request):
    """Configure alerting for a repo."""
    session = require_user(request)
    repo = get_repo(repo_id)
    if not repo or repo["user_id"] != session["user_id"]:
        raise HTTPException(status_code=404, detail="Repo not found")

    data = await request.json()
    set_alert_config(
        repo_id=repo_id,
        slack_webhook=data.get("slack_webhook"),
        discord_webhook=data.get("discord_webhook"),
        on_critical_only=data.get("on_critical_only", False),
    )
    return {"message": "Alert config saved"}


@app.delete("/api/repos/{repo_id}")
async def remove_repo(repo_id: str, request: Request):
    """Remove a monitored repo."""
    session = require_user(request)
    repo = get_repo(repo_id)
    if not repo or repo["user_id"] != session["user_id"]:
        raise HTTPException(status_code=404, detail="Repo not found")
    delete_repo_db(repo_id)
    return {"message": "Repo removed"}


@app.get("/api/repos/{repo_id}/scans")
async def get_repo_scans(repo_id: str, request: Request):
    session = require_user(request)
    repo = get_repo(repo_id)
    if not repo or repo["user_id"] != session["user_id"]:
        raise HTTPException(status_code=404, detail="Repo not found")
    scans = get_scans_for_repo(repo_id)
    return {"scans": scans}


# ========== PAGE ROUTES ==========


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page: landing for guests, dashboard for authenticated users."""
    session = get_session(request)
    if session:
        return templates.TemplateResponse("dashboard.html", {"request": request, "session": session})
    return templates.TemplateResponse("landing.html", {"request": request, "session": None})


@app.get("/repo/{repo_id}", response_class=HTMLResponse)
async def repo_detail(request: Request, repo_id: str):
    """Repository detail page."""
    session = require_user(request)
    return templates.TemplateResponse("repo_detail.html", {"request": request, "session": session, "repo_id": repo_id})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_results(request: Request, scan_id: str):
    """Scan results detail page."""
    session = require_user(request)
    return templates.TemplateResponse("scan_results.html", {"request": request, "session": session, "scan_id": scan_id})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    session = require_user(request)
    return templates.TemplateResponse("settings.html", {"request": request, "session": session})
