"""Main secret detection scanner."""

import os
import sys
import json
from typing import List, Dict
from loguru import logger
try:
    from src.patterns import SecretMatcher
except ModuleNotFoundError:
    from patterns import SecretMatcher


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.setup_logging()
        self.results = []

    def setup_logging(self):
        """Setup logging."""
        log_level = self.config.get("log_level", "INFO")
        logger.remove()
        logger.add(sys.stderr, level=log_level, format="<level>{message}</level>")

    def scan_file(self, filepath: str, content: str) -> List[Dict]:
        """Scan a single file for secrets."""
        logger.debug(f"Scanning file: {filepath}")
        
        secrets = SecretMatcher.find_secrets(content)
        
        # Check if filename itself is suspicious
        secret_file_patterns = SecretMatcher.find_secret_files(filepath)
        if secret_file_patterns:
            logger.warning(f"⚠️  Suspicious filename: {filepath}")
        
        # Add file location to each secret
        for secret in secrets:
            secret["file"] = filepath
            if secret_file_patterns:
                secret["file_pattern_match"] = secret_file_patterns
        
        return secrets

    def scan_directory(self, directory: str, exclude_patterns: List[str] = None) -> List[Dict]:
        """Scan a directory for secrets."""
        exclude_patterns = exclude_patterns or [".git", "node_modules", ".venv", "dist", "build", "__pycache__"]
        secrets = []
        
        logger.info(f"📁 Scanning directory: {directory}")
        
        for root, dirs, files in os.walk(directory):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_patterns]
            
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        file_secrets = self.scan_file(filepath, content)
                        secrets.extend(file_secrets)
                except Exception as e:
                    logger.debug(f"Error scanning {filepath}: {e}")
        
        return secrets

    def scan_text(self, text: str) -> List[Dict]:
        """Scan raw text for secrets."""
        return SecretMatcher.find_secrets(text)

    def generate_report(self, secrets: List[Dict]) -> Dict:
        """Generate a summary report."""
        report = {
            "total_secrets": len(secrets),
            "by_type": {},
            "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "files_affected": set(),
            "secrets": secrets
        }
        
        for secret in secrets:
            secret_type = secret.get("type", "Unknown")
            report["by_type"][secret_type] = report["by_type"].get(secret_type, 0) + 1
            
            confidence = secret.get("confidence", "MEDIUM")
            report["by_confidence"][confidence] += 1
            
            if "file" in secret:
                report["files_affected"].add(secret["file"])
        
        report["files_affected"] = list(report["files_affected"])
        return report


def main():
    """CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="🔐 Secrets Hygiene Monitor - Detect and track secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/scanner.py --dir .
  python src/scanner.py --file config.yaml
  python src/scanner.py --text 'AKIAIOSFODNN7EXAMPLE'my
        """
    )
    parser.add_argument("--file", help="Scan a single file")
    parser.add_argument("--dir", help="Scan a directory", default=".")
    parser.add_argument("--text", help="Scan raw text")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    config = {
        "log_level": "DEBUG" if args.verbose else "INFO"
    }
    
    scanner = Scanner(config)
    
    if args.file:
        logger.info(f"📄 Scanning file: {args.file}")
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        secrets = scanner.scan_file(args.file, content)
    elif args.text:
        logger.info("📝 Scanning text input")
        secrets = scanner.scan_text(args.text)
    elif args.dir:
        secrets = scanner.scan_directory(args.dir)
    else:
        parser.print_help()
        return
    
    report = scanner.generate_report(secrets)
    
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("\n" + "="*60)
        print(f"🔐 SECRETS HYGIENE MONITOR REPORT")
        print("="*60)
        print(f"Total Secrets Found: {report['total_secrets']}")
        print(f"Files Affected: {len(report['files_affected'])}")
        print(f"\nBy Type:")
        for secret_type, count in sorted(report['by_type'].items()):
            print(f"  • {secret_type}: {count}")
        print(f"\nBy Confidence:")
        for confidence, count in report['by_confidence'].items():
            print(f"  • {confidence}: {count}")
        
        if secrets:
            print(f"\n⚠️  DETECTED SECRETS:")
            for i, secret in enumerate(secrets[:10], 1):
                print(f"\n  [{i}] {secret.get('type', 'Unknown')}")
                print(f"      File: {secret.get('file', 'N/A')}")
                print(f"      Confidence: {secret.get('confidence', 'N/A')}")
            if len(secrets) > 10:
                print(f"\n  ... and {len(secrets) - 10} more")
        else:
            logger.info("✅ No secrets detected!")
        
        print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
