"""test_system.py -- Full system verification."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Use a fresh temp DB
db_fd, DB_PATH = tempfile.mkstemp(suffix=".db")
os.close(db_fd)
os.environ["DATABASE_PATH"] = DB_PATH

from api.main import app
from api.database import (
    init_db, create_user, add_repo, get_user_repos,
    add_scan, get_scans_for_repo, get_latest_scan,
    set_alert_config, get_alert_config,
)
from api.security import validate_repo_url, validate_local_path
from api.scanner import GITLEAKS_PATH
from api.worker import _diff_findings

results = []

def check(status, msg):
    results.append((status, msg))

# 1. Imports (already passed)
check("PASS", "All modules import cleanly")

# 2. Gitleaks
if GITLEAKS_PATH:
    check("PASS", f"Gitleaks installed: {GITLEAKS_PATH}")
else:
    check("WARN", "Gitleaks not installed -- install on VPS with: brew install gitleaks / apt install gitleaks")

# 3. URL validation
assert validate_repo_url("https://github.com/user/repo") is None
assert validate_repo_url("https://localhost/evil") is not None
assert validate_repo_url("file:///etc/passwd") is not None
assert validate_repo_url("https://10.0.0.1/r") is not None
assert validate_repo_url("https://user:pass@github.com/r") is not None
check("PASS", "URL validation (5 cases)")

# 4. Path validation
assert validate_local_path("/tmp") is None
assert validate_local_path("/etc") is not None
assert validate_local_path(os.path.expanduser("~/.ssh")) is not None
check("PASS", "Path validation (3 cases)")

# 5. Database full CRUD
init_db()
check("PASS", "Database tables created")

user_id = create_user(github_id=12345, login="testuser", email="test@test.com", access_token="test_token_123")
check("PASS", f"User created: {user_id}")

repo_id = add_repo(user_id, "test-repo", "https://github.com/test/repo")
repos = get_user_repos(user_id)
assert len(repos) == 1
check("PASS", "Repo add/list works")

scan_id = add_scan(repo_id, user_id, "completed", 3, 1, 1, 1,
                   [{"rule_id": "aws", "secret": "AKIAIOSFODNN7EXAMPLE"}], "manual")
scans = get_scans_for_repo(repo_id)
assert len(scans) == 1
check("PASS", "Scan storage/retrieval works")

latest = get_latest_scan(repo_id)
assert latest is not None and latest["total_findings"] == 3
check("PASS", "Latest scan query works")

# Alert config
set_alert_config(repo_id, slack_webhook="https://hooks.slack.com/test")
cfg = get_alert_config(repo_id)
assert cfg is not None and cfg["slack_webhook"] == "https://hooks.slack.com/test"
check("PASS", "Alert config CRUD works")

# 6. Diff findings
prev = [{"file": "a.py", "line": 10, "rule_id": "aws"}]
curr = [
    {"file": "a.py", "line": 10, "rule_id": "aws"},
    {"file": "b.py", "line": 5, "rule_id": "github"},
]
new = _diff_findings(curr, prev)
assert len(new) == 1 and new[0]["file"] == "b.py"
check("PASS", "New-finding detection (diff works)")

# 7. FastAPI routes
routes = [r.path for r in app.routes if hasattr(r, "path")]
expected = [
    "/api/health", "/api/dashboard", "/api/repos", "/api/scan",
    "/auth/github", "/auth/github/callback", "/webhooks/github",
]
for ep in expected:
    found = any(ep in r for r in routes)
    check("PASS" if found else "FAIL", f"Route {ep}")

# Summary
print("\n=== SYSTEM VERIFICATION ===\n")
pass_count = warn_count = fail_count = 0
for status, msg in results:
    if status == "PASS":
        pass_count += 1
        print(f"  [PASS] {msg}")
    elif status == "WARN":
        warn_count += 1
        print(f"  [WARN] {msg}")
    else:
        fail_count += 1
        print(f"  [FAIL] {msg}")
print(f"\n{pass_count} pass, {warn_count} warn, {fail_count} fail out of {len(results)}")
if fail_count == 0:
    print("\n>>> SYSTEM READY FOR DEPLOY <<<")
else:
    print("\n>>> ISSUES FOUND - DO NOT DEPLOY <<<")

# Cleanup
os.unlink(DB_PATH)
