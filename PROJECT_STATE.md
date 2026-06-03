# Secrets Hygiene Monitor -- Project State
# ========================================
# Last updated: 2026-06-01
# This file is the SINGLE SOURCE OF TRUTH for the current project state.
# Read this first before doing anything.

## What This Is
A SaaS product that monitors GitHub repositories for leaked secrets (API keys, tokens, credentials).
Users login with GitHub OAuth, register repos, and the system auto-scans them on every push (webhook)
and on a schedule (every 6 hours). Alerts via Slack/Discord when new secrets are found.

## Current Status: MVP COMPLETE, LOCAL TESTING IN PROGRESS
- All code is written and committed to GitHub
- Server is running locally at http://127.0.0.1:8000
- GitHub OAuth is configured and working (redirects to GitHub)
- User has NOT yet tested the full login flow in browser
- NOT yet deployed to VPS

## Repository
- Local: /Users/kaushik/Documents/GitHub/secrets-hygiene-monitor
- Remote: https://github.com/Kaushik-hub306/secrets-hygiene-monitor
- Branch: main
- Latest commit: a66b3ba

## File Structure
```
api/main.py         -- FastAPI app: all routes, OAuth, webhooks, dashboard UI (676 lines)
api/database.py     -- SQLite: users, repos, scans, alert_configs tables
api/worker.py       -- Background scan worker + scheduler + diff findings + alert dispatch
api/security.py     -- URL validation, path blocking, SSRF protection
api/scanner.py      -- Gitleaks integration (scan_git_repo, scan_directory)
api/alerts.py       -- Slack + Discord webhook notifications
api/models.py       -- Pydantic models (ScanRequest, ScanResponse, etc.)
api/__init__.py     -- Empty
run.py              -- Server entry point (reads .env for HOST/PORT)
deploy.sh           -- One-command VPS deployment script (Ubuntu 24.04)
test_system.py      -- Full system verification script
requirements.txt    -- fastapi, uvicorn, pydantic<2, python-dotenv, loguru, requests
.env                -- OAuth credentials (DO NOT COMMIT - gitignored)
.env.example        -- Template
src/scanner.py      -- Old CLI scanner (kept for reference, not used)
src/patterns.py     -- Old regex patterns (kept for reference, not used)
```

## Key Architecture Decisions
- Gitleaks (v8.18.4) as scanning engine (not custom regex)
- SQLite for MVP (swap to Postgres later)
- In-memory session store (swap to signed cookies/Redis later)
- Background thread for scheduler (not APScheduler -- simpler)
- Diff-based alerting: only alerts on NEW findings vs previous scan
- Secrets truncated to 30 chars in storage, never logged in full

## Security Measures
- SSRF blocked (localhost, private IPs, file:// schemes)
- Path traversal blocked (.ssh, .gnupg, .env, /etc, /root, etc.)
- CORS locked to configured origins (not wildcard)
- Rate limiting: 60 req/min per IP
- Webhook signature verification (HMAC-SHA256)
- .env file gitignored
- Systemd service runs as non-root user with NoNewPrivileges

## OAuth Credentials (in .env, gitignored)
- GITHUB_CLIENT_ID=Ov23liNnCGKj2INBPkmd
- GITHUB_CLIENT_SECRET=c953ecbc5ce552d3d951e8a7df465df8bf06b240
- Callback URL: http://127.0.0.1:8000/auth/github/callback

## How To Run Locally
```bash
cd /Users/kaushik/Documents/GitHub/secrets-hygiene-monitor
python3 run.py
# Server: http://127.0.0.1:8000
# Health: curl http://127.0.0.1:8000/api/health
```

## How To Test
1. Open http://127.0.0.1:8000 in browser
2. Click "Login with GitHub" -- redirects to GitHub auth
3. Authorize, get redirected back logged in
4. Add a repo to monitor
5. Click "Scan Now" or wait for auto-scan
6. View results on dashboard

## API Endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/health | No | Health check |
| GET | /auth/github | No | Start GitHub OAuth flow |
| GET | /auth/github/callback | No | OAuth callback |
| GET | /auth/logout | No | Clear session |
| GET | /auth/me | No | Check auth status |
| GET | /api/dashboard | Yes | Get repos + scans |
| GET | /api/github/repos | Yes | List user's GitHub repos |
| POST | /api/repos | Yes | Add repo to monitor |
| GET | /api/repos | Yes | List monitored repos |
| POST | /api/repos/{id}/scan | Yes | Trigger manual scan |
| POST | /api/repos/{id}/alert | Yes | Configure alerts |
| DELETE | /api/repos/{id} | Yes | Remove repo |
| GET | /api/repos/{id}/scans | Yes | Get scan history |
| POST | /webhooks/github | No | GitHub push webhook |

## Known Issues / TODO
- Dashboard JS had `toLowerCase()` bug (fixed in main.py line 518)
- `/api/scan` old route removed; now use `/api/repos/{id}/scan`
- No Stripe billing yet (free for now)
- No SSL/HTTPS yet (local only)
- Session store is in-memory (lost on restart)
- Scheduler runs in background thread (not persistent across deploys)

## Next Steps (Priority Order)
1. User tests GitHub login flow in browser
2. Deploy to Lightsail VPS using deploy.sh
3. Set up SSL with certbot on VPS
4. Create GitHub webhook for push events
5. Add Stripe billing (free tier + paid)
6. Add user onboarding flow

## VPS Info
- Provider: AWS Lightsail
- OS: Ubuntu 24.04
- Hermes: Already installed
- Deploy script: deploy.sh (in repo root)
- App will run as: /opt/secrets-monitor (systemd service)

## Important Notes for New Model
- NEVER commit .env file (contains real OAuth secrets)
- The .gitignore was broken (used literal \n) -- already fixed
- pydantic v1 is used (not v2) due to build issues on macOS
- `model_dump()` does NOT work -- use `.dict()` instead
- Server binds to 127.0.0.1 by default (change to 0.0.0.0 for VPS)
- Gitleaks must be installed on VPS: `apt install gitleaks` or use deploy.sh
