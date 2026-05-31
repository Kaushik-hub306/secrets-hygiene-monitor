"""Secret detection patterns and entropy analysis."""

import re
import math
from typing import List, Tuple, Dict
from enum import Enum


class SecretType(Enum):
    """Types of secrets we detect."""
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    GITHUB_TOKEN = "GitHub Token"
    GITHUB_OAUTH = "GitHub OAuth Token"
    SLACK_TOKEN = "Slack API Token"
    SENDGRID_API_KEY = "SendGrid API Key"
    STRIPE_API_KEY = "Stripe API Key"
    MONGODB_URI = "MongoDB Connection String"
    DATABASE_PASSWORD = "Database Password"
    SSH_PRIVATE_KEY = "SSH Private Key"
    JWT_TOKEN = "JWT Token"
    GENERIC_SECRET = "High Entropy String"
    HEROKU_API_KEY = "Heroku API Key"
    TWILIO_API_KEY = "Twilio API Key"
    PRIVATE_KEY = "Private Key"


class Patterns:
    """Regex patterns for secret detection."""

    # AWS
    AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
    AWS_SECRET_KEY = re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    )

    # GitHub
    GITHUB_PAT = re.compile(r"ghp_[0-9a-zA-Z]{36}")
    GITHUB_OAUTH = re.compile(r"gho_[0-9a-zA-Z]{36}")
    GITHUB_APP_TOKEN = re.compile(r"ghu_[0-9a-zA-Z]{36}")
    GITHUB_REFRESH_TOKEN = re.compile(r"ghr_[0-9a-zA-Z]{36}")

    # Slack
    SLACK_BOT_TOKEN = re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,26}")
    SLACK_USER_TOKEN = re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}")
    SLACK_WEBHOOK = re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}")

    # APIs
    SENDGRID_API_KEY = re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}")
    STRIPE_API_KEY = re.compile(r"(?:sk_live|pk_live|rk_live)_[a-zA-Z0-9]{24,}")
    HEROKU_API_KEY = re.compile(r"heroku_[a-z0-9]{36}")
    TWILIO_API_KEY = re.compile(r"AC[a-zA-Z0-9]{32}")

    # Databases
    MONGODB_URI = re.compile(
        r"mongodb(?:\+srv)?://[a-zA-Z0-9_.-]+(?::[a-zA-Z0-9_.-]+)?@[a-zA-Z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9_.-]*"
    )

    # Private Keys
    RSA_PRIVATE_KEY = re.compile(
        r"-----BEGIN RSA PRIVATE KEY-----[^-]*-----END RSA PRIVATE KEY-----",
        re.DOTALL
    )
    OPENSSH_PRIVATE_KEY = re.compile(
        r"-----BEGIN OPENSSH PRIVATE KEY-----[^-]*-----END OPENSSH PRIVATE KEY-----",
        re.DOTALL
    )

    # JWT
    JWT_TOKEN = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )


class EntropyAnalyzer:
    """Analyze entropy of strings to detect likely secrets."""

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        
        entropy = 0.0
        for char in set(s):
            p = s.count(char) / len(s)
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def is_likely_secret(s: str, min_entropy: float = 3.5, min_length: int = 20) -> bool:
        """Check if string is likely a secret based on entropy."""
        if len(s) < min_length:
            return False
        
        entropy = EntropyAnalyzer.calculate_entropy(s)
        return entropy >= min_entropy

    @staticmethod
    def find_high_entropy_strings(text: str, min_entropy: float = 4.0) -> List[Tuple[str, float]]:
        """Find all high-entropy strings in text."""
        words = re.split(r'[\s=:,;\"\'\\()/\\-_]+', text)
        candidates = []
        
        for word in words:
            if len(word) >= 20:
                entropy = EntropyAnalyzer.calculate_entropy(word)
                if entropy >= min_entropy:
                    candidates.append((word, entropy))
        
        return sorted(candidates, key=lambda x: x[1], reverse=True)


class SecretMatcher:
    """Match strings against secret patterns."""

    PATTERN_MAP = [
        (Patterns.AWS_ACCESS_KEY, SecretType.AWS_ACCESS_KEY),
        (Patterns.AWS_SECRET_KEY, SecretType.AWS_SECRET_KEY),
        (Patterns.GITHUB_PAT, SecretType.GITHUB_TOKEN),
        (Patterns.GITHUB_OAUTH, SecretType.GITHUB_OAUTH),
        (Patterns.SLACK_BOT_TOKEN, SecretType.SLACK_TOKEN),
        (Patterns.SLACK_USER_TOKEN, SecretType.SLACK_TOKEN),
        (Patterns.SLACK_WEBHOOK, SecretType.SLACK_TOKEN),
        (Patterns.SENDGRID_API_KEY, SecretType.SENDGRID_API_KEY),
        (Patterns.STRIPE_API_KEY, SecretType.STRIPE_API_KEY),
        (Patterns.MONGODB_URI, SecretType.MONGODB_URI),
        (Patterns.HEROKU_API_KEY, SecretType.HEROKU_API_KEY),
        (Patterns.RSA_PRIVATE_KEY, SecretType.SSH_PRIVATE_KEY),
        (Patterns.OPENSSH_PRIVATE_KEY, SecretType.SSH_PRIVATE_KEY),
        (Patterns.JWT_TOKEN, SecretType.JWT_TOKEN),
    ]

    @staticmethod
    def find_secrets(text: str) -> List[Dict]:
        """Find all secrets in text."""
        secrets = []
        seen = set()

        # Pattern matching
        for pattern, secret_type in SecretMatcher.PATTERN_MAP:
            matches = pattern.finditer(text)
            for match in matches:
                secret_value = match.group(0)
                if secret_value not in seen:
                    secrets.append({
                        "type": secret_type.value,
                        "value": secret_value[:50],  # Truncate for safety
                        "confidence": "HIGH",
                    })
                    seen.add(secret_value)

        # Entropy-based detection
        high_entropy = EntropyAnalyzer.find_high_entropy_strings(text, min_entropy=4.0)
        for entropy_string, entropy_score in high_entropy[:10]:
            if entropy_string not in seen and len(entropy_string) >= 30:
                secrets.append({
                    "type": SecretType.GENERIC_SECRET.value,
                    "value": entropy_string[:50],
                    "entropy": round(entropy_score, 2),
                    "confidence": "MEDIUM" if entropy_score < 5.0 else "HIGH",
                })
                seen.add(entropy_string)

        return secrets

    @staticmethod
    def find_secret_files(path: str) -> List[str]:
        """Find files that likely contain secrets."""
        secret_filenames = [
            r"\.env",
            r"secrets?\.\w+",
            r"config\.\w+",
            r"credentials\.\w+",
            r"keys?\.\w+",
            r"\.aws",
            r"\.ssh",
            r"id_rsa",
        ]
        
        matches = []
        for pattern in secret_filenames:
            if re.search(pattern, path, re.IGNORECASE):
                matches.append(pattern)
        
        return matches