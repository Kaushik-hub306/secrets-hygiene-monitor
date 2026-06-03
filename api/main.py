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


# ========== DASHBOARD UI ==========

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = get_session(request)
    auth_section = ""
    if session:
        auth_section = f'<p style="color:#64748b;font-size:0.85rem;">Logged in as {session["login"]} | <a href="/auth/logout" style="color:#3b8f6f;">Logout</a></p>'
    else:
        auth_section = '<a href="/auth/github" style="color:#3b8f6f;text-decoration:none;font-size:0.9rem;">Login with GitHub to get started</a>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secrets Hygiene Monitor</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.2rem; margin: 1.5rem 0 0.75rem; color: #94a3b8; }}
  .subtitle {{ color: #64748b; margin-bottom: 1.5rem; }}
  .card {{ background: #1e2130; border: 1px solid #2d3748; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
  .card h3 {{ margin-bottom: 0.5rem; }}
  input, button, select {{ padding: 0.6rem 1rem; border-radius: 6px; border: 1px solid #374151; background: #1a1d2e; color: #e2e8f0; font-size: 0.95rem; }}
  input {{ width: 100%; margin-bottom: 0.5rem; }}
  input:focus {{ outline: none; border-color: #3b82f6; }}
  button {{ cursor: pointer; background: #3b82f6; border-color: #3b82f6; color: white; font-weight: 500; }}
  button:hover {{ background: #2563eb; }}
  button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
  button.danger {{ background: transparent; border-color: #ef4444; color: #ef4444; padding: 0.3rem 0.6rem; font-size: 0.8rem; }}
  button.danger:hover {{ background: #ef444420; }}
  .finding {{ padding: 0.75rem; border-left: 3px solid; margin-bottom: 0.5rem; background: #161b26; border-radius: 0 6px 6px 0; }}
  .finding.CRITICAL {{ border-color: #ef4444; }}
  .finding.HIGH {{ border-color: #f97316; }}
  .finding.MEDIUM {{ border-color: #eab308; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 99px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
  .badge.CRITICAL {{ background: #ef444420; color: #ef4444; }}
  .badge.HIGH {{ background: #f9731620; color: #f97316; }}
  .badge.MEDIUM {{ background: #eab30820; color: #eab308; }}
  .stats {{ display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  .stat {{ flex: 1; min-width: 80px; text-align: center; padding: 0.75rem; background: #1e2130; border-radius: 8px; border: 1px solid #2d3748; }}
  .stat .number {{ font-size: 1.5rem; font-weight: 700; }}
  .stat .label {{ font-size: 0.7rem; color: #64748b; text-transform: uppercase; }}
  .stat.critical .number {{ color: #ef4444; }}
  .stat.high .number {{ color: #f97316; }}
  .stat.medium .number {{ color: #eab308; }}
  .repo-card {{ display: flex; justify-content: space-between; align-items: flex-start; padding: 0.75rem; border-bottom: 1px solid #2d3748; }}
  .repo-card:last-child {{ border-bottom: none; }}
  .repo-info {{ flex: 1; }}
  .repo-actions {{ display: flex; gap: 0.5rem; }}
  .secure-note {{ font-size: 0.8rem; color: #64748b; margin-top: 0.5rem; }}
  .status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.4rem; }}
  .status-dot.active {{ background: #22c55e; }}
  .status-dot.inactive {{ background: #64748b; }}
  #message {{ padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; display: none; }}
  #message.success {{ display: block; background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }}
  #message.error {{ display: block; background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }}
  .row {{ display: flex; gap: 0.5rem; align-items: flex-end; }}
  .row input {{ flex: 1; }}
</style>
</head>
<body>
<div class="container">
  <h1>Secrets Hygiene Monitor</h1>
  <p class="subtitle">24/7 automated secret detection for your repositories</p>
  {auth_section}

  <div id="message"></div>

  <div id="guest-view">
    <div class="card" style="text-align:center;padding:3rem;">
      <h3>Welcome</h3>
      <p style="color:#64748b;margin:1rem 0;">Connect your GitHub account to start monitoring your repositories for leaked secrets.</p>
      <a href="/auth/github" style="display:inline-block;padding:0.75rem 1.5rem;background:#3b82f6;color:white;text-decoration:none;border-radius:6px;font-weight:500;">Login with GitHub</a>
    </div>
  </div>

  <div id="dashboard-view" style="display:none;">
    <h2>Monitored Repos</h2>
    <div class="card" id="repo-list"><p style="color:#64748b;">No repos yet. Add one below.</p></div>

    <h2>Add Repository</h2>
    <div class="card">
      <div id="add-repo-form">
        <div class="row">
          <input type="text" id="repoUrl" placeholder="https://github.com/user/repo" style="flex:2;" />
          <input type="text" id="repoBranch" placeholder="Branch" value="main" style="width:100px;" />
          <button onclick="addRepo()">Add</button>
        </div>
        <p class="secure-note">Or pick from your GitHub repos below:</p>
        <button onclick="loadGitHubRepos()" style="background:#374151;margin-top:0.5rem;">Load my GitHub repos</button>
        <div id="github-repo-list" style="margin-top:0.75rem;"></div>
      </div>
    </div>

    <h2>Recent Scans</h2>
    <div class="card" id="scan-list"><p style="color:#64748b;">No scans yet.</p></div>
  </div>
</div>

<script>
var isAuthenticated = {"true" if session else "false"};

function showMsg(msg, type) {{
  var el = document.getElementById('message');
  el.textContent = msg;
  el.className = type;
  setTimeout(function() {{ el.style.display = 'none'; }}, 5000);
}}

function init() {{
  if (isAuthenticated) {{
    document.getElementById('guest-view').style.display = 'none';
    document.getElementById('dashboard-view').style.display = 'block';
    loadDashboard();
  }}
}}

async function loadDashboard() {{
  try {{
    var res = await fetch('/api/dashboard');
    var data = await res.json();
    if (!data.authenticated) {{
      isAuthenticated = false;
      document.getElementById('guest-view').style.display = 'block';
      document.getElementById('dashboard-view').style.display = 'none';
      return;
    }}
    renderRepos(data.repos);
    renderScans(data.scans);
  }} catch(e) {{
    showMsg('Failed to load dashboard: ' + e.message, 'error');
  }}
}}

function renderRepos(repos) {{
  var el = document.getElementById('repo-list');
  if (!repos || repos.length === 0) {{
    el.innerHTML = '<p style="color:#64748b;">No repos yet. Add one below.</p>';
    return;
  }}
  el.innerHTML = repos.map(function(r) {{
    var lastScan = r.last_scan;
    var scanInfo = lastScan
      ? lastScan.total_findings + ' findings (last: ' + lastScan.created_at.slice(0,10) + ')'
      : 'Not scanned yet';
    return '<div class="repo-card">' +
      '<div class="repo-info">' +
        '<span class="status-dot active"></span><strong>' + r.name + '</strong>' +
        '<div style="font-size:0.8rem;color:#64748b;">' + r.url + ' \u00b7 ' + scanInfo + '</div>' +
      '</div>' +
      '<div class="repo-actions">' +
        '<button onclick="scanRepo(\\'' + r.id + '\\')">Scan Now</button>' +
        '<button class="danger" onclick="removeRepo(\\'' + r.id + '\\')">Remove</button>' +
      '</div>' +
    '</div>';
  }});
}}

function renderScans(scans) {{
  var el = document.getElementById('scan-list');
  if (!scans || scans.length === 0) {{
    el.innerHTML = '<p style="color:#64748b;">No scans yet.</p>';
    return;
  }}
  el.innerHTML = scans.slice(0,10).map(function(s) {{
    return '<div class="repo-card">' +
      '<div class="repo-info">' +
        '<strong>' + s.repo_name + '</strong>' +
        '<div style="font-size:0.8rem;color:#64748b;">' +
        s.total_findings + ' findings \u00b7 ' + s.triggered_by + ' \u00b7 ' + s.created_at.slice(0,16) +
        '</div>' +
      '</div>' +
    '</div>';
  }});
}}

async function addRepo() {{
  var url = document.getElementById('repoUrl').value.trim();
  var branch = document.getElementById('repoBranch').value.trim() || 'main';
  if (!url) {{ showMsg('Enter a repo URL', 'error'); return; }}
  try {{
    var res = await fetch('/api/repos', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{url: url, branch: branch}}),
    }});
    var data = await res.json();
    if (!res.ok) {{ showMsg(data.detail || 'Failed', 'error'); return; }}
    showMsg(data.message, 'success');
    document.getElementById('repoUrl').value = '';
    loadDashboard();
  }} catch(e) {{
    showMsg('Failed: ' + e.message, 'error');
  }}
}}

async function loadGitHubRepos() {{
  try {{
    var res = await fetch('/api/github/repos');
    var data = await res.json();
    if (!res.ok) {{ showMsg(data.detail || 'Failed', 'error'); return; }}
    var el = document.getElementById('github-repo-list');
    el.innerHTML = data.repos.slice(0,20).map(function(r) {{
      return '<div class="repo-card" style="padding:0.5rem;">' +
        '<div class="repo-info"><strong>' + r.name + '</strong>' +
        '<div style="font-size:0.75rem;color:#64748b;">' + (r.private ? 'Private' : 'Public') + '</div></div>' +
        '<button onclick="addGitHubRepo(\\'' + r.url + '\\', \\'' + r.name + '\\', ' + r.id + ', \\'' + r.default_branch + '\\')">Add</button>' +
      '</div>';
    }});
  }} catch(e) {{
    showMsg('Failed: ' + e.message, 'error');
  }}
}}

async function addGitHubRepo(url, name, githubId, branch) {{
  try {{
    var res = await fetch('/api/repos', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{url: url, name: name, branch: branch, github_repo_id: githubId}}),
    }});
    var data = await res.json();
    if (!res.ok) {{ showMsg(data.detail || 'Failed', 'error'); return; }}
    showMsg(data.message, 'success');
    loadDashboard();
  }} catch(e) {{
    showMsg('Failed: ' + e.message, 'error');
  }}
}}

async function scanRepo(repoId) {{
  try {{
    var res = await fetch('/api/repos/' + repoId + '/scan', {{method: 'POST'}});
    var data = await res.json();
    if (!res.ok) {{ showMsg(data.detail || 'Scan failed', 'error'); return; }}
    showMsg('Scan started! ' + (data.total_findings || 0) + ' findings.', 'success');
    setTimeout(loadDashboard, 3000);
  }} catch(e) {{
    showMsg('Failed: ' + e.message, 'error');
  }}
}}

async function removeRepo(repoId) {{
  if (!confirm('Remove this repo from monitoring?')) return;
  try {{
    var res = await fetch('/api/repos/' + repoId, {{method: 'DELETE'}});
    var data = await res.json();
    if (!res.ok) {{ showMsg(data.detail || 'Failed', 'error'); return; }}
    showMsg('Repo removed', 'success');
    loadDashboard();
  }} catch(e) {{
    showMsg('Failed: ' + e.message, 'error');
  }}
}}

init();
</script>
</body>
</html>"""
