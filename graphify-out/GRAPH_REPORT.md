# Graph Report - .  (2026-07-02)

## Corpus Check
- Corpus is ~24,917 words - fits in a single context window. You may not need a graph.

## Summary
- 241 nodes · 496 edges · 17 communities (13 shown, 4 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.78)
- Token cost: 40,000 input · 75,435 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Frontend UI  Templates|Frontend UI / Templates]]
- [[_COMMUNITY_Pattern Detection Engine|Pattern Detection Engine]]
- [[_COMMUNITY_Repos API Management|Repos API Management]]
- [[_COMMUNITY_Scan Infrastructure|Scan Infrastructure]]
- [[_COMMUNITY_API Models & Health|API Models & Health]]
- [[_COMMUNITY_Scanner Orchestration|Scanner Orchestration]]
- [[_COMMUNITY_Database Core|Database Core]]
- [[_COMMUNITY_Database CRUD|Database CRUD]]
- [[_COMMUNITY_Security & Auth|Security & Auth]]
- [[_COMMUNITY_Alerts & Notifications|Alerts & Notifications]]
- [[_COMMUNITY_Gitleaks Integration|Gitleaks Integration]]
- [[_COMMUNITY_GitHub Webhooks|GitHub Webhooks]]
- [[_COMMUNITY_App Initialization|App Initialization]]
- [[_COMMUNITY_Deploy|Deploy]]
- [[_COMMUNITY_App Runner|App Runner]]
- [[_COMMUNITY_Hermes Agent|Hermes Agent]]

## God Nodes (most connected - your core abstractions)
1. `$()` - 27 edges
2. `Secrets Hygiene Monitor` - 22 edges
3. `get_db()` - 21 edges
4. `toast()` - 20 edges
5. `require_user()` - 14 edges
6. `scan_repo_and_store()` - 14 edges
7. `request()` - 12 edges
8. `loadDashboard()` - 12 edges
9. `Scanner` - 10 edges
10. `init()` - 10 edges

## Surprising Connections (you probably didn't know these)
- `Secrets Hygiene Monitor` --references--> `Daily GitHub Actions Scan Workflow`  [INFERRED]
  PROJECT_STATE.md → .github/workflows/scan.yml
- `Secrets Hygiene Monitor` --references--> `Ubuntu VPS Deploy Script`  [INFERRED]
  PROJECT_STATE.md → QUICK_DEPLOY.md
- `Secrets Hygiene Monitor` --conceptually_related_to--> `Aspirational AWS Architecture (Lambda, DynamoDB, S3)`  [INFERRED]
  PROJECT_STATE.md → README.md
- `Secrets Hygiene Monitor` --conceptually_related_to--> `Repository Detail View`  [INFERRED]
  PROJECT_STATE.md → templates/repo_detail.html
- `Secrets Hygiene Monitor` --conceptually_related_to--> `Dashboard Monitoring UI`  [INFERRED]
  PROJECT_STATE.md → templates/dashboard.html

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Secrets Detection and Alerting Pipeline** — project_state_github_oauth, project_state_gitleaks_engine_decision, templates_scan_results_findings_severity, project_state_slack_discord_alerts [INFERRED 0.85]
- **Deployment Infrastructure Stack** — project_state_fastapi_framework, project_state_sqlite_mvp_decision, project_state_systemd_service, quick_deploy_ubuntu_vps [INFERRED 0.85]
- **Security Boundary Measures** — project_state_ssrf_cors_security, project_state_webhook_hmac, project_state_rate_limiting, project_state_secrets_truncation [INFERRED 0.85]

## Communities (17 total, 4 thin omitted)

### Community 0 - "Frontend UI / Templates"
Cohesion: 0.09
Nodes (50): addGitHubRepo(), addRepoFromUrl(), appendScanLog(), confirmRemoveRepo(), copyApiKey(), copyCode(), el(), exportFindings() (+42 more)

### Community 1 - "Pattern Detection Engine"
Cohesion: 0.08
Nodes (23): Enum, EntropyAnalyzer, Patterns, Secret detection patterns and entropy analysis., Types of secrets we detect., Find all high-entropy strings in text., Match strings against secret patterns., Find all secrets in text. (+15 more)

### Community 2 - "Repos API Management"
Cohesion: 0.11
Nodes (29): get_repo(), get_user(), add_monitored_repo(), configure_alerts(), dashboard_data(), get_me(), get_repo_scans(), get_session() (+21 more)

### Community 3 - "Scan Infrastructure"
Cohesion: 0.10
Nodes (26): Daily GitHub Actions Scan Workflow, Background Thread Scheduler Decision, Diff-Based Alerting Strategy, FastAPI Web Framework, GitHub OAuth Authentication, Gitleaks Scanning Engine Decision, In-Memory Session Store Decision, Pydantic v1 Dependency Decision (+18 more)

### Community 4 - "API Models & Health"
Cohesion: 0.18
Nodes (14): health(), AlertConfig, HealthResponse, Repository and finding models., Request to scan a repository., A single secret finding., Response from a scan., Register a repository for monitoring. (+6 more)

### Community 5 - "Scanner Orchestration"
Cohesion: 0.23
Nodes (11): add_scan(), get_alert_config(), update_repo_scan_time(), Core scanning engine using Gitleaks., Clone a git repo and scan it.     Returns a list of findings, or None on failure, scan_git_repo(), _diff_findings(), Background scan worker and scheduler. (+3 more)

### Community 6 - "Database Core"
Cohesion: 0.21
Nodes (11): get_latest_scan(), get_user_repos(), init_db(), Create tables if they don't exist., github_login(), list_monitored_repos(), Secrets Hygiene Monitor - Full backend with OAuth, webhooks, and monitoring., Background thread that runs periodic scans. (+3 more)

### Community 7 - "Database CRUD"
Cohesion: 0.24
Nodes (11): create_user(), delete_repo_db(), get_db(), get_scans_for_repo(), get_user_by_github(), SQLite database layer for persistent storage., Get a database connection., update_repo_webhook() (+3 more)

### Community 8 - "Security & Auth"
Cohesion: 0.24
Nodes (7): add_repo(), set_alert_config(), Validate a repository URL.     Returns an error message if invalid, None if vali, Validate a local scan path.     Returns an error message if invalid, None if val, validate_local_path(), validate_repo_url(), test_system.py -- Full system verification.

### Community 9 - "Alerts & Notifications"
Cohesion: 0.29
Nodes (7): Alerting integrations., Send findings to a Slack webhook., Send findings to a Discord webhook., send_discord_alert(), send_slack_alert(), Send alerts to configured channels., _send_alerts()

### Community 10 - "Gitleaks Integration"
Cohesion: 0.25
Nodes (8): check_gitleaks(), _map_severity(), _normalize_findings(), Map a gitleaks finding to a severity level., Check if gitleaks is installed and available., Scan a directory using Gitleaks.     Returns a list of findings., Normalize gitleaks JSON output into our format., scan_directory()

### Community 11 - "GitHub Webhooks"
Cohesion: 0.40
Nodes (5): get_all_repos(), github_webhook(), Receive GitHub webhook events on push., Scan all registered repos. Run on a schedule., run_scheduled_scan()

## Knowledge Gaps
- **11 isolated node(s):** `deploy.sh script`, `FastAPI Web Framework`, `SSRF and CORS Security Measures`, `Webhook HMAC-SHA256 Verification`, `Rate Limiting 60 Requests per Minute` (+6 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get_db()` connect `Database CRUD` to `Repos API Management`, `Scanner Orchestration`, `Database Core`, `Security & Auth`, `GitHub Webhooks`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._
- **Why does `scan_repo_and_store()` connect `Scanner Orchestration` to `Repos API Management`, `Database Core`, `Database CRUD`, `Alerts & Notifications`, `GitHub Webhooks`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `Secrets Hygiene Monitor` (e.g. with `Daily GitHub Actions Scan Workflow` and `Ubuntu VPS Deploy Script`) actually correct?**
  _`Secrets Hygiene Monitor` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Secrets Hygiene Monitor - FastAPI backend.`, `Alerting integrations.`, `Send findings to a Slack webhook.` to the rest of the system?**
  _77 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Frontend UI / Templates` be split into smaller, more focused modules?**
  _Cohesion score 0.09461152882205513 - nodes in this community are weakly interconnected._
- **Should `Pattern Detection Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.08095238095238096 - nodes in this community are weakly interconnected._
- **Should `Repos API Management` be split into smaller, more focused modules?**
  _Cohesion score 0.11083743842364532 - nodes in this community are weakly interconnected._