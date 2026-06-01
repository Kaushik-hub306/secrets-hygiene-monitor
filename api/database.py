"""SQLite database layer for persistent storage."""

import os
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional

DB_PATH = os.getenv("DATABASE_PATH", "./data/secrets_monitor.db")


def get_db() -> sqlite3.Connection:
    """Get a database connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            github_id INTEGER UNIQUE,
            login TEXT,
            email TEXT,
            access_token TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS repos (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            branch TEXT DEFAULT 'main',
            github_repo_id INTEGER,
            webhook_id INTEGER,
            last_scan_at TEXT,
            last_scan_findings INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            repo_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            total_findings INTEGER DEFAULT 0,
            critical INTEGER DEFAULT 0,
            high INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0,
            findings_json TEXT DEFAULT '[]',
            triggered_by TEXT DEFAULT 'manual',
            created_at TEXT NOT NULL,
            FOREIGN KEY (repo_id) REFERENCES repos(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS alert_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id TEXT NOT NULL,
            slack_webhook TEXT,
            discord_webhook TEXT,
            on_critical_only INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (repo_id) REFERENCES repos(id)
        );

        CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_repos_user ON repos(user_id);
    """)
    conn.commit()
    conn.close()


# --- User operations ---

def create_user(github_id: int, login: str, email: str, access_token: str) -> str:
    import uuid
    user_id = str(uuid.uuid4())[:12]
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO users (id, github_id, login, email, access_token, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, github_id, login, email, access_token, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return user_id


def get_user_by_github(github_id: int) -> Optional[Dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE github_id = ?", (github_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user(user_id: str) -> Optional[Dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# --- Repo operations ---

def add_repo(user_id: str, name: str, url: str, branch: str = "main", github_repo_id: int = None) -> str:
    import uuid
    repo_id = str(uuid.uuid4())[:12]
    conn = get_db()
    conn.execute(
        "INSERT INTO repos (id, user_id, name, url, branch, github_repo_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (repo_id, user_id, name, url, branch, github_repo_id, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return repo_id


def get_user_repos(user_id: str) -> List[Dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM repos WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_repo(repo_id: str) -> Optional[Dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM repos WHERE id = ?", (repo_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_repos() -> List[Dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM repos").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_repo_webhook(repo_id: str, webhook_id: int):
    conn = get_db()
    conn.execute("UPDATE repos SET webhook_id = ? WHERE id = ?", (webhook_id, repo_id))
    conn.commit()
    conn.close()


def update_repo_scan_time(repo_id: str, findings: int):
    conn = get_db()
    conn.execute("UPDATE repos SET last_scan_at = ?, last_scan_findings = ? WHERE id = ?",
                 (datetime.utcnow().isoformat(), findings, repo_id))
    conn.commit()
    conn.close()


def delete_repo_db(repo_id: str):
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM alert_configs WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM repos WHERE id = ?", (repo_id,))
    conn.commit()
    conn.close()


# --- Scan operations ---

def add_scan(repo_id: str, user_id: str, status: str, total: int, critical: int, high: int, medium: int,
             findings: list, triggered_by: str = "manual") -> str:
    import uuid
    scan_id = str(uuid.uuid4())[:12]
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (id, repo_id, user_id, status, total_findings, critical, high, medium, findings_json, triggered_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, repo_id, user_id, status, total, critical, high, medium,
         json.dumps(findings), triggered_by, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return scan_id


def get_scans_for_repo(repo_id: str, limit: int = 20) -> List[Dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE repo_id = ? ORDER BY created_at DESC LIMIT ?",
        (repo_id, limit)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["findings"] = json.loads(d.get("findings_json", "[]"))
        del d["findings_json"]
        result.append(d)
    return result


def get_latest_scan(repo_id: str) -> Optional[Dict]:
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE repo_id = ? ORDER BY created_at DESC LIMIT 1", (repo_id,)
    ).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["findings"] = json.loads(d.get("findings_json", "[]"))
        del d["findings_json"]
        return d
    return None


# --- Alert config operations ---

def set_alert_config(repo_id: str, slack_webhook: str = None, discord_webhook: str = None, on_critical_only: bool = False):
    conn = get_db()
    conn.execute("DELETE FROM alert_configs WHERE repo_id = ?", (repo_id,))
    if slack_webhook or discord_webhook:
        conn.execute(
            "INSERT INTO alert_configs (repo_id, slack_webhook, discord_webhook, on_critical_only, created_at) VALUES (?, ?, ?, ?, ?)",
            (repo_id, slack_webhook, discord_webhook, int(on_critical_only), datetime.utcnow().isoformat()),
        )
    conn.commit()
    conn.close()


def get_alert_config(repo_id: str) -> Optional[Dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM alert_configs WHERE repo_id = ?", (repo_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
