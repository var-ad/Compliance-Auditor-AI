import os
import re
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

from app.graph.state import AuditState, Finding


async def run_github(state: AuditState) -> dict:
    try:
        load_dotenv()
        owner, repo = _parse_repo(state["repo_url"])
        if not owner or not repo:
            raise ValueError("Invalid GitHub repo URL")

        token = os.getenv("GITHUB_TOKEN")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

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

            branch_response = await client.get(f"/repos/{owner}/{repo}/branches/main/protection")
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

        return {"github_findings": findings}
    except Exception as exc:
        return {"github_findings": [], "error": str(exc)}


def _parse_repo(repo_url: str) -> tuple[str | None, str | None]:
    ssh_match = re.match(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$", repo_url)
    if ssh_match:
        return ssh_match.group("owner"), ssh_match.group("repo")

    parsed = urlparse(repo_url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != "github.com":
        return None, None
    parts = [part for part in parsed.path.strip("/").removesuffix(".git").split("/") if part]
    if len(parts) != 2:
        return None, None
    return parts[0], parts[1]


def _finding(severity: str, title: str, description: str, rule_id: str) -> Finding:
    return {
        "tool": "github",
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": None,
        "rule_id": rule_id,
    }
