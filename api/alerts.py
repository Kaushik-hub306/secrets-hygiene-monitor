"""Alerting integrations."""

import json
import urllib.request
from typing import List, Dict, Optional
from loguru import logger


def send_slack_alert(webhook_url: str, findings: List[Dict], repo_name: str) -> bool:
    """Send findings to a Slack webhook."""
    if not findings:
        return True

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🔐 Secrets detected in {repo_name}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Total findings:* {len(findings)}\n"
                    f"🔴 Critical: {len(critical)}  "
                    f"🟠 High: {len(high)}  "
                    f"🟡 Medium: {len(medium)}"
                ),
            },
        },
        {"type": "divider"},
    ]

    # Show up to 5 findings
    for f in findings[:5]:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{f.get('description', 'Unknown')}* ({f.get('severity', 'N/A')})\n"
                    f"• File: `{f.get('file', 'N/A')}` line {f.get('line', '?')}\n"
                    f"• Rule: `{f.get('rule_id', 'N/A')}`"
                ),
            },
        })

    if len(findings) > 5:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"_...and {len(findings) - 5} more findings_",
                }
            ],
        })

    payload = json.dumps({"blocks": blocks}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status == 200
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False


def send_discord_alert(webhook_url: str, findings: List[Dict], repo_name: str) -> bool:
    """Send findings to a Discord webhook."""
    if not findings:
        return True

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]

    # Discord embed
    description = f"**{len(findings)} secrets detected** in `{repo_name}`\n"
    description += f"🔴 Critical: {len(critical)} | 🟠 High: {len(high)} | 🟡 Medium: {len(medium)}\n\n"

    for f in findings[:5]:
        description += (
            f"**{f.get('description', 'Unknown')}** ({f.get('severity', 'N/A')})\n"
            f"`{f.get('file', 'N/A')}` line {f.get('line', '?')} • Rule: `{f.get('rule_id', 'N/A')}`\n\n"
        )

    if len(findings) > 5:
        description += f"_...and {len(findings) - 5} more findings_"

    color = 0xFF0000 if critical else (0xFF8C00 if high else 0xFFD700)

    payload = json.dumps({
        "embeds": [{
            "title": f"🔐 Secrets Hygiene Alert",
            "description": description,
            "color": color,
            "footer": {"text": "Secrets Hygiene Monitor"},
        }]
    }).encode()

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status in (200, 204)
    except Exception as e:
        logger.error(f"Discord alert failed: {e}")
        return False
