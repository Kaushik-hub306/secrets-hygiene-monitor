# Secrets Hygiene Monitor — ⏸️ On Hold

> Working prototype, paused while I ship [Loom](https://github.com/Kaushik-hub306/Loom). Not production-ready; not actively maintained.

Continuous secrets-leak scanning for GitHub repositories: register a repo and it gets scanned on push and on schedule using [Gitleaks](https://github.com/gitleaks/gitleaks), with alerts on new findings.

## What's here

- FastAPI backend with GitHub OAuth login and repo registration
- Scan worker wrapping Gitleaks v8 (commit-history scanning)
- Alerting via Slack/Discord webhooks (HMAC-verified)
- Security hardening: SSRF blocking, path-traversal guards, rate limiting, CORS lockdown
- Jinja2 + vanilla JS dashboard

## Status

Code-complete MVP, never deployed. Revisiting after Loom ships — leaked credentials in agent-driven workflows is exactly the kind of problem [Loom](https://github.com/Kaushik-hub306/Loom)'s security layer cares about.
