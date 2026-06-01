"""Security utilities."""

import re
from urllib.parse import urlparse
from typing import Optional


# Allowed URL schemes for repo cloning
ALLOWED_SCHEMES = {"https", "git", "ssh"}

# Allowed git hosts (empty = allow all, populate to restrict)
ALLOWED_GIT_HOSTS: set = set()  # e.g. {"github.com", "gitlab.com"}

# Blocked path patterns for local scan (prevent reading sensitive system files)
BLOCKED_PATH_PATTERNS = [
    r"^/etc/",
    r"^/private/etc/",
    r"^/root/",
    r"^/var/log/",
    r"^/proc/",
    r"^/sys/",
    r"/\.ssh(?:/|$)",
    r"/\.gnupg(?:/|$)",
    r"/\.aws/credentials$",
    r"/\.env(?:$|\\.)",
    r"/\\.npmrc$",
    r"/\.docker(?:/|$)",
    r"/\.kube(?:/|$)",
]

# Compiled blocked path regexes
_BLOCKED_PATH_RE = [re.compile(p) for p in BLOCKED_PATH_PATTERNS]


def validate_repo_url(url: str) -> Optional[str]:
    """
    Validate a repository URL.
    Returns an error message if invalid, None if valid.
    """
    if not url or len(url) > 2048:
        return "URL is empty or too long"

    # Block file:// and other dangerous schemes
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
        return f"URL scheme '{parsed.scheme}' is not allowed"

    # If host restriction is enabled, enforce it
    if ALLOWED_GIT_HOSTS and parsed.hostname and parsed.hostname not in ALLOWED_GIT_HOSTS:
        return f"Host '{parsed.hostname}' is not in the allowed list"

    # Block URLs with embedded credentials
    if parsed.username or parsed.password:
        return "URLs with embedded credentials are not allowed"

    # Block localhost/private IPs to prevent SSRF
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return "Localhost URLs are not allowed"
    if hostname.startswith("10.") or hostname.startswith("192.168.") or hostname.startswith("172."):
        return "Private network URLs are not allowed"

    return None


def validate_local_path(path: str) -> Optional[str]:
    """
    Validate a local scan path.
    Returns an error message if invalid, None if valid.
    """
    import os

    if not path:
        return "Path is empty"

    # Resolve to absolute path to prevent traversal
    real_path = os.path.realpath(path)

    # Check both the raw path and resolved path against blocked patterns
    for check_path in [path, real_path]:
        for pattern in _BLOCKED_PATH_RE:
            if pattern.search(check_path):
                return f"Path is in a blocked directory"

    return None
