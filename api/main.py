"""Secrets Hygiene Monitor - FastAPI backend with security hardening."""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from loguru import logger
from dotenv import load_dotenv

from api.models import (
    ScanRequest, ScanResponse, ScanResult,
    RepoRegister, AlertConfig, HealthResponse,
)
from api.scanner import scan_directory, scan_git_repo
from api.alerts import send_slack_alert, send_discord_alert
from api.security import validate_repo_url, validate_local_path

# Load .env file
load_dotenv()

# --- Configuration from environment ---
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000",
).split(",")

APP_ENV = os.getenv("APP_ENV", "development")
APP_HOST = os.getenv("HOST", "127.0.0.1")
APP_PORT = int(os.getenv("PORT", "8000"))
DISABLE_DOCS = os.getenv("DISABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Secrets Hygiene Monitor",
    description="Automated secrets detection for dev teams",
    version="0.1.0",
    docs_url="/docs" if not DISABLE_DOCS and APP_ENV != "production" else None,
    redoc_url="/redoc" if not DISABLE_DOCS and APP_ENV != "production" else None,
)

# CORS -- locked to configured origins, NOT wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# --- In-memory store for MVP (swap to SQLite/Postgres later) ---
repos: Dict[str, dict] = {}
scans: Dict[str, dict] = {}
scan_results: Dict[str, list] = {}


# --- Rate limiting (simple in-memory) ---
_rate_limit_store: Dict[str, List[float]] = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30     # requests per window


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting by IP."""
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.utcnow().timestamp()

    # Clean old entries
    if client_ip in _rate_limit_store:
        _rate_limit_store[client_ip] = [
            t for t in _rate_limit_store[client_ip]
            if now - t < RATE_LIMIT_WINDOW
        ]
    else:
        _rate_limit_store[client_ip] = []

    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

    _rate_limit_store[client_ip].append(now)
    response = await call_next(request)
    return response


# --- Endpoints ---

@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.post("/api/scan", response_model=ScanResponse)
async def scan_repo(request: ScanRequest):
    """Clone a repo and scan it for secrets."""
    from uuid import uuid4

    # Validate URL
    url_error = validate_repo_url(request.repo_url)
    if url_error:
        raise HTTPException(status_code=400, detail=f"Invalid repo URL: {url_error}")

    scan_id = str(uuid4())[:8]
    logger.info(f"[{scan_id}] Scanning {request.repo_url} (branch: {request.branch})")

    findings = scan_git_repo(request.repo_url, request.branch)

    if findings is None:
        raise HTTPException(status_code=400, detail="Failed to clone or scan the repository. Check the URL and branch.")

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    response = ScanResponse(
        scan_id=scan_id,
        repo_url=request.repo_url,
        status="completed",
        total_findings=len(findings),
        critical=critical,
        high=high,
        medium=medium,
        findings=[ScanResult(**f) for f in findings],
        message=f"Scan complete. {len(findings)} secrets found." if findings else "No secrets detected.",
    )

    # Store result (truncate secrets in stored data)
    stored = response.dict()
    for f in stored.get("findings", []):
        if f.get("secret"):
            f["secret"] = f["secret"][:30]  # Extra truncation for storage
    scans[scan_id] = stored

    return response


@app.post("/api/scan/local", response_model=ScanResponse)
async def scan_local_dir(path: str):
    """Scan a local directory (for self-hosted use)."""
    from uuid import uuid4

    # Validate path
    path_error = validate_local_path(path)
    if path_error:
        raise HTTPException(status_code=400, detail=f"Invalid path: {path_error}")

    if not os.path.isdir(path):
        raise HTTPException(status_code=400, detail=f"Path not found: {path}")

    scan_id = str(uuid4())[:8]
    findings = scan_directory(path)

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    return ScanResponse(
        scan_id=scan_id,
        repo_url=path,
        status="completed",
        total_findings=len(findings),
        critical=critical,
        high=high,
        medium=medium,
        findings=[ScanResult(**f) for f in findings],
        message=f"Scan complete. {len(findings)} secrets found." if findings else "No secrets detected.",
    )


@app.get("/api/scans")
async def list_scans():
    """List all completed scans (no secret values)."""
    return {
        "scans": [
            {
                "scan_id": k,
                "repo_url": v.get("repo_url"),
                "total_findings": v.get("total_findings"),
                "critical": v.get("critical"),
                "high": v.get("high"),
                "medium": v.get("medium"),
                "scanned_at": v.get("scanned_at"),
            }
            for k, v in scans.items()
        ]
    }


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get a specific scan result (secrets truncated to 30 chars)."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.post("/api/repos")
async def register_repo(repo: RepoRegister):
    """Register a repository for monitoring."""
    url_error = validate_repo_url(repo.repo_url)
    if url_error:
        raise HTTPException(status_code=400, detail=f"Invalid repo URL: {url_error}")

    repo_id = f"{repo.repo_url}-{datetime.utcnow().timestamp()}"
    repos[repo_id] = {
        "id": repo_id,
        "url": repo.repo_url,
        "name": repo.name or repo.repo_url.split("/")[-1].replace(".git", ""),
        "branch": repo.branch,
        "registered_at": datetime.utcnow().isoformat(),
        "alert_config": None,
    }
    return {"repo_id": repo_id, "message": f"Repo '{repos[repo_id]['name']}' registered."}


@app.get("/api/repos")
async def list_repos():
    """List registered repos."""
    return {"repos": list(repos.values())}


@app.post("/api/repos/{repo_id}/alert")
async def configure_alerts(repo_id: str, config: AlertConfig):
    """Configure alerting for a registered repo."""
    if repo_id not in repos:
        raise HTTPException(status_code=404, detail="Repo not found")
    repos[repo_id]["alert_config"] = config.dict()
    return {"message": "Alert config saved."}


@app.delete("/api/repos/{repo_id}")
async def delete_repo(repo_id: str):
    """Remove a registered repo."""
    if repo_id not in repos:
        raise HTTPException(status_code=404, detail="Repo not found")
    del repos[repo_id]
    return {"message": "Repo removed."}


# --- Static web UI ---
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the minimal dashboard."""
    return DASHBOARD_HTML


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secrets Hygiene Monitor</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  h2 { font-size: 1.3rem; margin: 1.5rem 0 0.75rem; color: #94a3b8; }
  .subtitle { color: #64748b; margin-bottom: 2rem; }
  .card { background: #1e2130; border: 1px solid #2d3748; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
  .card h3 { margin-bottom: 0.5rem; }
  input, button { padding: 0.6rem 1rem; border-radius: 6px; border: 1px solid #374151; background: #1a1d2e; color: #e2e8f0; font-size: 0.95rem; }
  input { width: 100%; margin-bottom: 0.5rem; }
  input:focus { outline: none; border-color: #3b82f6; }
  button { cursor: pointer; background: #3b82f6; border-color: #3b82f6; color: white; font-weight: 500; margin-top: 0.25rem; }
  button:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .finding { padding: 0.75rem; border-left: 3px solid; margin-bottom: 0.5rem; background: #161b26; border-radius: 0 6px 6px 0; }
  .finding.CRITICAL { border-color: #ef4444; }
  .finding.HIGH { border-color: #f97316; }
  .finding.MEDIUM { border-color: #eab308; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 99px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge.CRITICAL { background: #ef444420; color: #ef4444; }
  .badge.HIGH { background: #f9731620; color: #f97316; }
  .badge.MEDIUM { background: #eab30820; color: #eab308; }
  .stats { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 100px; text-align: center; padding: 1rem; background: #1e2130; border-radius: 8px; border: 1px solid #2d3748; }
  .stat .number { font-size: 2rem; font-weight: 700; }
  .stat .label { font-size: 0.8rem; color: #64748b; text-transform: uppercase; }
  .stat.critical .number { color: #ef4444; }
  .stat.high .number { color: #f97316; }
  .stat.medium .number { color: #eab308; }
  .repo-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; border-bottom: 1px solid #2d3748; }
  .repo-item:last-child { border-bottom: none; }
  .delete-btn { background: transparent; border: none; color: #ef4444; cursor: pointer; font-size: 0.85rem; padding: 0.25rem 0.5rem; margin: 0; }
  .delete-btn:hover { background: #ef444420; }
  #message { padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; display: none; }
  #message.success { display: block; background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }
  #message.error { display: block; background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
  .loading { opacity: 0.6; pointer-events: none; }
  .secure-note { font-size: 0.8rem; color: #64748b; margin-top: 0.5rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Secrets Hygiene Monitor</h1>
  <p class="subtitle">Scan your repositories for leaked credentials and secrets</p>
  <p class="secure-note">Secrets are truncated in responses and never stored in full.</p>

  <div id="message"></div>

  <div class="card">
    <h3>Scan a Repository</h3>
    <input type="text" id="repoUrl" placeholder="https://github.com/user/repo" />
    <input type="text" id="branch" placeholder="Branch (default: main)" value="main" style="width: 200px;" />
    <button onclick="startScan()" id="scanBtn">Scan</button>
  </div>

  <div id="results" style="display: none;">
    <h2>Scan Results</h2>
    <div class="stats">
      <div class="stat"><div class="number" id="total">0</div><div class="label">Total</div></div>
      <div class="stat critical"><div class="number" id="criticalCount">0</div><div class="label">Critical</div></div>
      <div class="stat high"><div class="number" id="highCount">0</div><div class="label">High</div></div>
      <div class="stat medium"><div class="number" id="mediumCount">0</div><div class="label">Medium</div></div>
    </div>
    <div id="findings"></div>
  </div>

  <h2>Recent Scans</h2>
  <div class="card" id="repoList"><p style="color: #64748b;">No scans yet. Scan a repo above to get started.</p></div>
</div>

<script>
  function showMsg(msg, type) {
    var el = document.getElementById('message');
    el.textContent = msg;
    el.className = type;
    setTimeout(function() { el.style.display = 'none'; }, 5000);
  }

  async function startScan() {
    var url = document.getElementById('repoUrl').value.trim();
    var branch = document.getElementById('branch').value.trim() || 'main';
    if (!url) { showMsg('Enter a repo URL', 'error'); return; }

    var btn = document.getElementById('scanBtn');
    btn.disabled = true; btn.textContent = 'Scanning...';
    document.getElementById('results').style.display = 'none';

    try {
      var res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: url, branch: branch }),
      });
      var data = await res.json();
      if (!res.ok) {
        showMsg(data.detail || 'Scan failed', 'error');
        return;
      }
      showResults(data);
      addScanEntry(data);
    } catch (e) {
      showMsg('Scan failed: ' + e.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'Scan';
    }
  }

  function showResults(data) {
    document.getElementById('results').style.display = 'block';
    document.getElementById('total').textContent = data.total_findings;
    document.getElementById('criticalCount').textContent = data.critical;
    document.getElementById('highCount').textContent = data.high;
    document.getElementById('mediumCount').textContent = data.medium;

    var container = document.getElementById('findings');
    if (!data.findings || data.findings.length === 0) {
      container.innerHTML = '<p style="color: #22c55e;">No secrets detected!</p>';
      return;
    }
    container.innerHTML = data.findings.map(function(f) {
      return '<div class="finding ' + f.severity + '">' +
        '<span class="badge ' + f.severity + '">' + f.severity + '</span> ' +
        '<strong>' + (f.description || f.rule_id) + '</strong>' +
        '<div style="font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem;">' +
        f.file + ':' + f.line + ' \u00b7 Rule: ' + f.rule_id +
        '</div></div>';
    }).join('');
  }

  function addScanEntry(data) {
    var list = document.getElementById('repoList');
    var div = document.createElement('div');
    div.className = 'repo-item';
    div.innerHTML = '<div>' +
      '<strong>' + data.repo_url + '</strong>' +
      '<div style="font-size: 0.8rem; color: #64748b;">' +
      data.total_findings + ' findings \u00b7 ' + data.scanned_at +
      '</div></div>' +
      '<button class="delete-btn" onclick="this.parentElement.remove()">Remove</button>';
    list.insertBefore(div, list.firstChild);
    var p = list.querySelector('p');
    if (p) p.remove();
  }
</script>
</body>
</html>
"""
