import logging
import os

import httpx

from app.graph.state import AuditState, Finding
from app.utils.config import GITHUB_TOKEN
from app.utils.git import SOURCE_GITHUB, parse_git_url

logger = logging.getLogger(__name__)


async def run_scan_repo_governance(state: AuditState) -> dict:
    """LangGraph node: check repo governance files and settings.

    Uses the local filesystem for all checks (clone is already available).
    Also checks the .github community health repo via API for GitHub sources.
    Supports GitHub, GitLab, Bitbucket, and any git host.
    """
    if state.get("error"):
        return {}

    local_path = state.get("local_path")
    if not local_path:
        return {"governance_findings": []}

    repo_url = state.get("repo_url", "")
    owner, repo_name, source_type = parse_git_url(repo_url)
    findings: list[Finding] = []

    # ── Filesystem checks (works for ALL source types) ────────────────

    # 1. SECURITY.md
    has_security = _local_file_exists(local_path, "SECURITY.md") or \
                   _local_file_exists(local_path, ".github", "SECURITY.md")

    if not has_security:
        # Also try the .github community health repo (GitHub-specific)
        if source_type == SOURCE_GITHUB and owner:
            has_security = await _remote_file_exists(
                owner, ".github", "SECURITY.md"
            )

    if not has_security:
        findings.append(_finding(
            severity="low",
            title="Security policy missing",
            description=(
                f"No SECURITY.md found in the repository. "
                "A security policy helps reporters responsibly "
                "disclose vulnerabilities."
            ),
            rule_id="gov_missing_security_policy",
            finding_type="missing_security_policy",
        ))

    # 2. CODEOWNERS
    has_codeowners = (
        _local_file_exists(local_path, "CODEOWNERS")
        or _local_file_exists(local_path, ".github", "CODEOWNERS")
    )

    if not has_codeowners and source_type == SOURCE_GITHUB and owner:
        has_codeowners = await _remote_file_exists(
            owner, ".github", "CODEOWNERS"
        )

    if not has_codeowners:
        findings.append(_finding(
            severity="info",
            title="CODEOWNERS file missing",
            description=(
                "No CODEOWNERS file found. Without it, "
                "PR reviews are not auto-assigned to the right teams."
            ),
            rule_id="gov_missing_codeowners",
            finding_type="missing_codeowners",
        ))

    # 3. Signed commits (GitHub API only)
    if source_type == SOURCE_GITHUB and owner and repo_name:
        signed = await _check_signed_commits(owner, repo_name)
        if signed is not None and not signed:
            findings.append(_finding(
                severity="low",
                title="Signed commits not enforced",
                description="Default branch does not require signed commits.",
                rule_id="gov_unsigned_commits",
                finding_type="unsigned_commits",
            ))

    # 4–6. Informational checks (no findings emitted)
    has_license = (
        _local_file_exists(local_path, "LICENSE")
        or _local_file_exists(local_path, "LICENSE.md")
    )
    has_contributing = _local_file_exists(local_path, "CONTRIBUTING.md")
    has_dependabot = (
        _local_file_exists(local_path, ".github", "dependabot.yml")
        or _local_file_exists(local_path, ".github", "dependabot.yaml")
        or _local_file_exists(local_path, "renovate.json")
        or _local_file_exists(local_path, ".renovaterc")
    )

    logger.info(
        "Governance: security=%s codeowners=%s signed=%s "
        "license=%s contributing=%s deps=%s",
        has_security, has_codeowners,
        "checked" if source_type == SOURCE_GITHUB else "n/a",
        has_license, has_contributing, has_dependabot,
    )

    logger.info("Governance scan found %d findings", len(findings))
    return {"governance_findings": findings}


# ── Local filesystem helpers ────────────────────────────────────────────


def _local_file_exists(base: str, *parts: str) -> bool:
    """Check if a file exists at base/parts."""
    path = os.path.join(base, *parts)
    return os.path.isfile(path)


# ── Remote API helpers (GitHub-specific) ────────────────────────────────


async def _remote_file_exists(
    owner: str, repo: str, path: str
) -> bool:
    """Check if a file exists in a GitHub repo via the Contents API."""
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=headers,
            timeout=15,
        ) as client:
            resp = await client.get(f"/repos/{owner}/{repo}/contents/{path}")
            return resp.status_code == 200
    except Exception:
        return False


async def _check_signed_commits(owner: str, repo: str) -> bool | None:
    """Check if signed commits are required on the default branch.
    Returns True if enforced, False if not, None if uncheckable."""
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=headers,
            timeout=15,
        ) as client:
            # Get default branch
            repo_resp = await client.get(f"/repos/{owner}/{repo}")
            if repo_resp.status_code != 200:
                return None
            default_branch = repo_resp.json().get("default_branch", "main")

            sig_resp = await client.get(
                f"/repos/{owner}/{repo}/branches/{default_branch}/protection/"
                "required_signatures"
            )
            if sig_resp.status_code == 200:
                return sig_resp.json().get("enabled", False)
            return False
    except Exception:
        return None


def _finding(severity: str, title: str, description: str, rule_id: str, finding_type: str) -> Finding:
    return {
        "tool": "governance",
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": None,
        "rule_id": rule_id,
        "finding_type": finding_type,
    }
