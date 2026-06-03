"""Background scan worker and scheduler."""

import asyncio
import json
from datetime import datetime
from typing import List, Dict, Optional
from loguru import logger

from api.scanner import scan_git_repo
from api.alerts import send_slack_alert, send_discord_alert
from api.database import (
    get_all_repos, get_repo, get_latest_scan, get_alert_config,
    add_scan, update_repo_scan_time,
)


async def scan_repo_and_store(repo_id: str, user_id: str, repo_url: str, branch: str,
                                triggered_by: str = "manual") -> Dict:
    """
    Scan a repo, store results, and trigger alerts if secrets found.
    Returns the scan record.
    """
    logger.info(f"[scan_worker] Starting {triggered_by} scan of {repo_url}")

    # Run the blocking scan in a thread pool
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, scan_git_repo, repo_url, branch)

    if findings is None:
        logger.error(f"[scan_worker] Scan failed for {repo_url}")
        add_scan(repo_id, user_id, "failed", 0, 0, 0, 0, [], triggered_by)
        return {"status": "failed", "findings": []}

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    # Truncate secrets for storage
    stored_findings = []
    for f in findings:
        sf = dict(f)
        if sf.get("secret"):
            sf["secret"] = sf["secret"][:30]
        stored_findings.append(sf)

    scan_id = add_scan(repo_id, user_id, "completed", len(findings),
                       critical, high, medium, stored_findings, triggered_by)
    update_repo_scan_time(repo_id, len(findings))

    result = {
        "scan_id": scan_id,
        "repo_id": repo_id,
        "repo_url": repo_url,
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "findings": stored_findings,
        "triggered_by": triggered_by,
    }

    # Check if these are NEW findings compared to last scan
    latest = get_latest_scan(repo_id)
    prev_findings = []
    if latest:
        # Get the one before latest
        from api.database import get_db
        conn = get_db()
        rows = conn.execute(
            "SELECT findings_json FROM scans WHERE repo_id = ? ORDER BY created_at DESC LIMIT 2",
            (repo_id,)
        ).fetchall()
        conn.close()
        if len(rows) > 1:
            prev_findings = json.loads(rows[1]["findings_json"] or "[]")

    new_findings = _diff_findings(findings, prev_findings)

    # Send alerts
    if new_findings:
        alert_config = get_alert_config(repo_id)
        if alert_config:
            alert_data = {**result, "findings": new_findings}
            await _send_alerts(alert_config, alert_data)

    logger.info(f"[scan_worker] Complete: {len(findings)} findings ({len(new_findings)} new)")
    return result


def _diff_findings(current: List[Dict], previous: List[Dict]) -> List[Dict]:
    """Find findings that weren't in the previous scan."""
    if not previous:
        return current

    prev_keys = set()
    for f in previous:
        key = f.get("file", "") + ":" + str(f.get("line", 0)) + ":" + f.get("rule_id", "")
        prev_keys.add(key)

    new = []
    for f in current:
        key = f.get("file", "") + ":" + str(f.get("line", 0)) + ":" + f.get("rule_id", "")
        if key not in prev_keys:
            new.append(f)
    return new


async def _send_alerts(alert_config: Dict, scan_result: Dict):
    """Send alerts to configured channels."""
    repo_url = scan_result.get("repo_url", "unknown")
    findings = scan_result.get("findings", [])

    if alert_config.get("on_critical_only") and not any(f.get("severity") == "CRITICAL" for f in findings):
        return

    if alert_config.get("slack_webhook"):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, send_slack_alert, alert_config["slack_webhook"], findings, repo_url
            )
        except Exception as e:
            logger.error(f"[alerts] Slack failed: {e}")

    if alert_config.get("discord_webhook"):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, send_discord_alert, alert_config["discord_webhook"], findings, repo_url
            )
        except Exception as e:
            logger.error(f"[alerts] Discord failed: {e}")


async def run_scheduled_scan():
    """Scan all registered repos. Run on a schedule."""
    repos = get_all_repos()
    if not repos:
        return

    logger.info(f"[scheduler] Running scheduled scan of {len(repos)} repos")

    for repo in repos:
        try:
            result = await scan_repo_and_store(
                repo_id=repo["id"],
                user_id=repo["user_id"],
                repo_url=repo["url"],
                branch=repo.get("branch", "main"),
                triggered_by="scheduled",
            )
            # Small delay between scans to be polite
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"[scheduler] Failed scanning {repo['url']}: {e}")

    logger.info(f"[scheduler] Scheduled scan complete")
