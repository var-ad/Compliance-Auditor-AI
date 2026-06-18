import logging

import httpx

from app.graph.state import AuditState, Finding
from app.utils.config import GITHUB_TOKEN
from app.utils.git import parse_github_url

logger = logging.getLogger(__name__)


async def run_github(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    try:
        owner, repo = parse_github_url(state["repo_url"])
        if not owner or not repo:
            raise ValueError("Invalid GitHub repo URL")

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        findings: list[Finding] = []
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=headers,
            timeout=30,
        ) as client:
            org_response = await client.get(f"/orgs/{owner}")
            if org_response.status_code == 200:
                org_data = org_response.json()
                if not org_data.get("two_factor_requirement_enabled"):
                    findings.append(
                        _finding(
                            severity="high",
                            title="MFA not enforced",
                            description="Organisation does not enforce 2FA for members",
                            rule_id="github_mfa",
                        )
                    )

            branch_response = await client.get(
                f"/repos/{owner}/{repo}/branches/main/protection"
            )
            if branch_response.status_code == 404:
                findings.append(
                    _finding(
                        severity="high",
                        title="Branch protection missing",
                        description="Default branch has no protection rules",
                        rule_id="github_branch_protection",
                    )
                )
            elif branch_response.status_code < 400:
                branch_data = branch_response.json()
                if not branch_data.get("required_pull_request_reviews"):
                    findings.append(
                        _finding(
                            severity="high",
                            title="Branch protection missing",
                            description="Default branch has no protection rules",
                            rule_id="github_branch_protection",
                        )
                    )

            repo_response = await client.get(f"/repos/{owner}/{repo}")
            repo_response.raise_for_status()
            repo_data = repo_response.json()
            if repo_data.get("private") is False:
                findings.append(
                    _finding(
                        severity="medium",
                        title="Repository is public",
                        description="Repository is publicly accessible",
                        rule_id="github_public_repo",
                    )
                )

        logger.info("GitHub API found %d findings", len(findings))
        return {"github_findings": findings}
    except Exception as exc:
        logger.error("GitHub scan failed: %s", exc)
        return {"github_findings": [], "error": str(exc)}


def _finding(severity: str, title: str, description: str, rule_id: str) -> Finding:
    return {
        "tool": "github",
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": None,
        "rule_id": rule_id,
    }
