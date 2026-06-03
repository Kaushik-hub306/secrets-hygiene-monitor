"""Core scanning engine using Gitleaks."""

import os
import json
import shutil
import tempfile
import subprocess
from typing import List, Dict, Optional
from loguru import logger


GITLEAKS_PATH = shutil.which("gitleaks")


def check_gitleaks() -> bool:
    """Check if gitleaks is installed and available."""
    if GITLEAKS_PATH:
        return True
    # Try to download it for the user
    logger.error(
        "gitleaks not found. Install it: "
        "brew install gitleaks (macOS) or "
        "wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64 -O /usr/local/bin/gitleaks"
    )
    return False


def scan_directory(path: str) -> List[Dict]:
    """
    Scan a directory using Gitleaks.
    Returns a list of findings.
    """
    if not check_gitleaks():
        return []

    cmd = [
        GITLEAKS_PATH,
        "detect",
        "--source", path,
        "--report-format", "json",
        "--report-path", "-",
        "--redact",
        "--no-banner",
        "--no-color",
        "--no-git",        # Scan files directly, don't require git history
    ]

    logger.info(f"Running gitleaks on {path}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode == 0:
        # No leaks found
        return []

    if result.returncode == 1:
        # Leaks found -- gitleaks exits 1 when it finds secrets
        try:
            findings = json.loads(result.stdout)
            return _normalize_findings(findings, path)
        except json.JSONDecodeError:
            logger.error("gitleaks parse error while reading JSON report")
            return []

    logger.error(f"gitleaks error (exit {result.returncode}): {result.stderr[:500]}")
    return []


def scan_git_repo(url: str, branch: str = "main") -> Optional[List[Dict]]:
    """
    Clone a git repo and scan it.
    Returns a list of findings, or None on failure.
    """
    tmpdir = tempfile.mkdtemp(prefix="secrets-scan-")
    try:
        clone_cmd = ["git", "clone", "--depth", "50", "--branch", branch, "--single-branch", url, tmpdir]
        clone_result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
        if clone_result.returncode != 0:
            logger.error(f"Clone failed: {clone_result.stderr[:300]}")
            return None
        return scan_directory(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _normalize_findings(findings: list, source_path: str) -> List[Dict]:
    """Normalize gitleaks JSON output into our format."""
    normalized = []
    for finding in findings:
        normalized.append({
            "rule_id": finding.get("RuleID", "unknown"),
            "description": finding.get("Description", ""),
            "secret": finding.get("Secret", "")[:50] if finding.get("Secret") else "",
            "file": finding.get("File", ""),
            "line": finding.get("StartLine", 0),
            "column": finding.get("StartColumn", 0),
            "match": finding.get("Match", "")[:100] if finding.get("Match") else "",
            "severity": _map_severity(finding),
            "source": source_path,
        })
    return normalized


def _map_severity(finding: Dict) -> str:
    """Map a gitleaks finding to a severity level."""
    rule = finding.get("RuleID", "").lower()
    secret = finding.get("Secret", "").lower()

    # Critical secret types
    critical_keywords = ["aws", "private_key", "ssh", "stripe", "sendgrid"]
    high_keywords = ["github", "slack", "token", "api_key", "apikey", "password"]

    for kw in critical_keywords:
        if kw in rule or kw in secret:
            return "CRITICAL"
    for kw in high_keywords:
        if kw in rule or kw in secret:
            return "HIGH"
    return "MEDIUM"
