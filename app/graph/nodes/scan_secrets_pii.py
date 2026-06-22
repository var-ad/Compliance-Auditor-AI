import asyncio
import logging
import os
import re
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII REGEX PATTERNS (v1 — targeted, low false-positive)
# ---------------------------------------------------------------------------

PII_PATTERNS: list[dict] = [
    {
        "name": "email_address",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        "regex": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    },
    {
        "name": "phone_india",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        # +91 9876543210 or 09876543210 (10 digits with optional +91/0 prefix)
        "regex": re.compile(r"(?:\+?91[-.\s]?)?[6-9]\d{9}"),
    },
    {
        "name": "aadhaar_like",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        # 12 consecutive digits — watch for false positives with long numbers
        "regex": re.compile(r"\b[2-9]\d{11}\b"),
    },
    {
        "name": "pan_card",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        # 5 uppercase letters + 4 digits + 1 uppercase letter
        "regex": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]{1}\b"),
    },
    {
        "name": "credit_card",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        # 13-16 digits, optionally grouped by spaces/dashes (basic Luhn-free check)
        "regex": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    },
    {
        "name": "ip_address",
        "finding_type": "pii_in_source",
        "severity_base": "medium",
        # IPv4 in test/fixture files
        "regex": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    },
    {
        "name": "inline_credential",
        "finding_type": "pii_in_source",
        "severity_base": "high",
        # Matches "password": "somevalue", "secret":"val", etc. in JSON/code.
        # Requires at least 4 chars after the colon to avoid trivial false matches.
        "regex": re.compile(
            r'"(?:password|passwd|secret|api_key|apikey|api_secret'
            r'|auth_token|access_key|private_key)"\s*:\s*"[^"]{4,}"',
            re.I,
        ),
    },
]

# Directories that reduce severity from high → medium (likely test/fixture data)
_LOW_SEVERITY_DIRS: tuple = (
    "test", "tests", "__tests__", "spec", "__spec__",
    "fixture", "fixtures", "mock", "mocks", "seed", "seeds",
    "stub", "stubs", "factory", "factories", "sample", "samples",
    "example", "examples", "demo", "demos",
)


def _is_test_or_fixture(file_path: str) -> bool:
    """Check if a file path is in a test/fixture/seed directory."""
    parts = file_path.replace("\\", "/").split("/")
    return any(d in parts for d in _LOW_SEVERITY_DIRS)


def _redact_match(match: re.Match) -> str:
    """Replace matched secret with a safe truncated form.

    Shows first 4 and last 2 chars of the match; replaces middle with [REDACTED].
    """
    raw = match.group()
    if len(raw) <= 8:
        return f"{raw[:2]}...[REDACTED]"
    return f"{raw[:4]}...[REDACTED]{raw[-2:]}"


def _redact_text(text: str, pattern: re.Pattern) -> str:
    """Redact all matches of `pattern` in `text`."""
    return pattern.sub(lambda m: _redact_match(m), text)


# ---------------------------------------------------------------------------
# PII SCANNER (sync, runs in a thread)
# ---------------------------------------------------------------------------

def _run_pii_scan(repo_path: str) -> list[Finding]:
    """Walk all tracked files in repo_path and match PII regex patterns.

    Returns Finding dicts with redacted descriptions.
    """
    findings: list[Finding] = []

    if not os.path.isdir(repo_path):
        logger.warning("PII scan: repo path %s not found", repo_path)
        return findings

    # Collect files via git ls-files (tracked files only)
    git_path = shutil.which("git")
    if not git_path:
        logger.warning("PII scan: git not found, skipping")
        return findings

    try:
        result = subprocess.run(
            [git_path, "-C", repo_path, "ls-files"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            logger.warning("PII scan: git ls-files failed: %s", result.stderr[:200])
            return findings
        tracked_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except Exception as exc:
        logger.warning("PII scan: git ls-files error: %s", exc)
        return findings

    for rel_path in tracked_files:
        full_path = os.path.join(repo_path, rel_path)
        if not os.path.isfile(full_path):
            continue

        # Skip binary files and large files (> 1 MB)
        try:
            stat = os.stat(full_path)
            if stat.st_size > 1_048_576:
                continue
        except OSError:
            continue

        try:
            with open(full_path, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception:
            continue

        is_test = _is_test_or_fixture(rel_path)
        line_offset = 0

        for pattern_def in PII_PATTERNS:
            regex = pattern_def["regex"]
            finding_type = pattern_def["finding_type"]
            base_severity = pattern_def["severity_base"]
            # Test/fixture files downgrade: high → medium, medium → low
            if is_test:
                if base_severity == "high":
                    severity = "medium"
                elif base_severity == "medium":
                    severity = "low"
                else:
                    severity = base_severity
            else:
                severity = base_severity

            for match in regex.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                matched_text = match.group()

                # Skip common false positives
                if _is_false_positive(matched_text, rel_path, content, match):
                    continue

                redacted = _redact_text(matched_text, regex)
                snippet_start = max(0, match.start() - 40)
                snippet_end = min(len(content), match.end() + 40)
                snippet = content[snippet_start:snippet_end].replace("\n", " ").strip()

                findings.append({
                    "tool": "secrets_pii",
                    "severity": severity,
                    "title": f"PII: {pattern_def['name']} detected",
                    "description": (
                        f"PII pattern '{pattern_def['name']}' matched in {rel_path}:{line_number}. "
                        f"Matched value: {redacted}. "
                        f"Context: \"{_redact_text(snippet, regex)}\""
                    ),
                    "file_path": rel_path,
                    "rule_id": f"pii_{pattern_def['name']}",
                    "finding_type": finding_type,
                })

                line_offset += 1

    logger.info("PII scan found %d findings", len(findings))
    return findings


PLACEHOLDER_EMAILS = {
    "you@example.com", "user@example.com", "email@example.com",
    "test@test.com", "example@example.com", "admin@example.com",
    "name@example.com", "email@domain.com", "user@domain.com",
    "test@example.com", "your@example.com", "me@example.com",
}


def _is_false_positive(matched_text: str, file_path: str, content: str, match: re.Match) -> bool:
    """Filter out common false positives from PII patterns."""
    # Skip version strings like "1.2.3.4" or semver
    if re.match(r"^\d+\.\d+\.\d+\.\d+", matched_text):
        return True
    # Skip matches that are part of a hex/commit-hash string.
    # The matched text itself captures only the phone-like portion (10 digits),
    # so also check whether surrounding characters are hex.
    start = match.start()
    end = match.end()
    # Look at up to 5 chars before and after for hex context
    hex_before = sum(1 for i in range(max(0, start - 5), start)
                     if content[i] in "0123456789abcdefABCDEF")
    hex_after = sum(1 for i in range(end, min(len(content), end + 5))
                    if content[i] in "0123456789abcdefABCDEF")
    if hex_before + hex_after >= 4:
        return True
    # Also check if the match itself is long and mostly hex-ish
    if len(matched_text) >= 12:
        hex_chars = sum(c in "abcdefABCDEF" for c in matched_text)
        digit_chars = sum(c.isdigit() for c in matched_text)
        if hex_chars > 0 and hex_chars + digit_chars >= len(matched_text) * 0.85:
            return True
    # Skip common test IPs
    if matched_text in ("127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "localhost"):
        return True
    # Skip placeholder/demo email addresses (common in UI templates)
    if matched_text.lower() in PLACEHOLDER_EMAILS:
        return True
    # Skip any email at @example.com — this domain is reserved by RFC 2606
    # for documentation and examples. jane@example.com is not a real leak.
    if re.search(r"@example\.com$", matched_text, re.I):
        return True
    # Skip emails in placeholder attributes (HTML input placeholders)
    line_start = max(0, content.rfind("\n", 0, match.start()))
    line_end = content.find("\n", match.end())
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].lower()
    if "placeholder" in line:
        return True
    # Skip findings in documentation files when context shows they're
    # examples, not real credentials. Matches README.md curl examples,
    # docs/*.md API usage snippets, and similar.
    ext = os.path.splitext(file_path.lower())[1]
    if ext in (".md", ".rst", ".txt"):
        doc_keywords = {"example", "curl", "sample", "demo", "usage",
                        "illustration", "snippet", "test@", "@example"}
        if any(kw in line for kw in doc_keywords):
            return True
    # Skip IPs in private ranges (common in configs)
    if re.match(r"^10\.\d+\.\d+\.\d+$", matched_text):
        return True
    if re.match(r"^192\.168\.\d+\.\d+$", matched_text):
        return True
    if re.match(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$", matched_text):
        return True
    # Skip lines that look like code (variable assignments to test values)
    line_start = content.rfind("\n", 0, match.start())
    if line_start == -1:
        line_start = 0
    line = content[line_start:content.find("\n", match.end())].strip()
    if line.startswith("//") or line.startswith("#") or line.startswith("/*"):
        return False  # Don't skip comments — they can contain real PII
    return False


# ---------------------------------------------------------------------------
# GITLEAKS SCANNER (sync, runs in a thread)
# ---------------------------------------------------------------------------

def _find_gitleaks() -> str | None:
    """Resolve gitleaks binary path."""
    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        return gitleaks
    # Common Windows install locations
    for candidate in [
        os.path.expanduser("~/go/bin/gitleaks.exe"),
        os.path.expanduser("~/go/bin/gitleaks"),
        "C:\\Program Files\\gitleaks\\gitleaks.exe",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _run_gitleaks_scan(repo_path: str) -> list[Finding]:
    """Run gitleaks against full git history and return findings.

    Gitleaks scans the entire commit history for secrets/credentials.
    Uses --log-opts='--all' to scan all branches.
    """
    gitleaks = _find_gitleaks()
    if not gitleaks:
        logger.warning("Gitleaks not installed — secrets scan will be empty. "
                       "Install from https://github.com/gitleaks/gitleaks/releases")
        return []

    try:
        result = subprocess.run(
            [gitleaks, "detect", "--source", repo_path,
             "--log-opts", "--all", "--report-format", "json", "--no-color"],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks scan timed out after 300s")
        return []
    except FileNotFoundError:
        logger.warning("Gitleaks binary not found at %s", gitleaks)
        return []
    except Exception as exc:
        logger.warning("Gitleaks scan failed: %s", exc)
        return []

    # Gitleaks exits 1 when it finds secrets, 0 when none found
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    if not stdout.strip():
        logger.info("Gitleaks: no secrets found")
        return []

    try:
        leaks = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("Gitleaks: failed to parse JSON output: %s", stdout[:500])
        return []

    findings: list[Finding] = []
    if isinstance(leaks, dict):
        leaks = [leaks]
    for leak in leaks:
        if not isinstance(leak, dict):
            continue

        rule_id = (leak.get("RuleID") or leak.get("rule_id", "gitleaks_match"))
        description = (leak.get("Description") or leak.get("description", "") or "")
        file_path = (leak.get("File") or leak.get("file", ""))
        start_line = leak.get("StartLine") or leak.get("start_line", 0)
        commit = (leak.get("Commit") or leak.get("commit", ""))[:8]
        secret = leak.get("Secret") or leak.get("secret", "") or ""
        author = (leak.get("Author") or leak.get("author", "") or "")

        # Determine finding_type from the gitleaks rule
        finding_type = _classify_gitleaks_rule(rule_id, description, secret)

        # Determine severity: committed secrets are always at least high
        if finding_type in ("jwt_exposed", "private_key_exposed", "cloud_credentials_exposed"):
            severity = "critical"
        elif finding_type == "hardcoded_secret":
            severity = "critical"
        else:
            severity = "high"

        # Redact the secret from output
        redacted_secret = f"{secret[:4]}...[REDACTED]{secret[-2:]}" if len(secret) > 6 else "[REDACTED]"

        desc = (
            f"Secret detected by gitleaks: {description} "
            f"in {file_path}:{start_line} "
            f"(commit: {commit}, author: {author}). "
            f"Matched value: {redacted_secret}"
        )

        findings.append({
            "tool": "secrets_pii",
            "severity": severity,
            "title": f"Secret: {rule_id}",
            "description": desc,
            "file_path": file_path,
            "rule_id": f"gitleaks_{rule_id}",
            "finding_type": finding_type,
        })

    logger.info("Gitleaks found %d findings", len(findings))
    return findings


def _classify_gitleaks_rule(rule_id: str, description: str, secret: str) -> str:
    """Map gitleaks rule IDs to finding_type keys matching CONTROL_MAP."""
    rid = rule_id.lower()
    desc = description.lower()
    secret_lower = secret.lower()

    # JWT patterns
    if "jwt" in rid or "json" in rid and "token" in rid:
        return "jwt_exposed"

    # Private key patterns
    if "private-key" in rid or "private_key" in rid or "ssh" in rid:
        return "private_key_exposed"
    if "pem" in secret_lower or "begin" in secret_lower and "key" in secret_lower:
        return "private_key_exposed"
    if "rsa" in rid or "dsa" in rid or "ec" in rid and "key" in rid:
        return "private_key_exposed"

    # Cloud provider patterns
    if "aws" in rid or "amazon" in rid or "gcp" in rid or "google" in rid or "azure" in rid:
        return "cloud_credentials_exposed"
    if "github" in rid or "gitlab" in rid or "slack" in rid or "discord" in rid and "token" in rid:
        return "cloud_credentials_exposed"
    if "generic-api-key" in rid or "api_key" in rid:
        return "cloud_credentials_exposed"

    # Default: generic hardcoded secret
    return "hardcoded_secret"


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_secrets_pii(state: AuditState) -> dict:
    """LangGraph node: run gitleaks + PII scans in parallel.

    Returns secrets_findings appended to state.
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"secrets_findings": []}

    try:
        # Run gitleaks and PII scans concurrently
        gitleaks_findings, pii_findings = await asyncio.gather(
            asyncio.to_thread(_run_gitleaks_scan, repo_path),
            asyncio.to_thread(_run_pii_scan, repo_path),
        )

        all_findings = gitleaks_findings + pii_findings
        logger.info("Secrets+PII scan: %d gitleaks + %d PII = %d total",
                     len(gitleaks_findings), len(pii_findings), len(all_findings))
        return {"secrets_findings": all_findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("Secrets+PII scan failed: %s", err_text)
        return {"secrets_findings": []}
