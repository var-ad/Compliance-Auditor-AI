import logging

import httpx

from app.graph.state import AuditState, Finding
from app.utils.config import GITHUB_TOKEN
from app.utils.git import SOURCE_GITHUB, parse_git_url

logger = logging.getLogger(__name__)


async def _has_security_policy(client: httpx.AsyncClient, owner: str, repo: str, host: str = "github.com") -> str | None:
    """Check if the repo has a security policy. Returns a URL or None."""
    for attempt_owner in (owner, ".github"):
        try:
            resp = await client.get(f"/repos/{attempt_owner}/{repo}/contents/SECURITY.md")
            if resp.status_code == 200:
                return f"https://{host}/{attempt_owner}/{repo}/blob/master/SECURITY.md"
        except Exception:
            pass
    return None


async def run_github(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    # Only run for GitHub-hosted repos
    if state.get("input_source") != SOURCE_GITHUB:
        logger.info("GitHub checks: skipping (source=%s)", state.get("input_source"))
        return {"github_findings": []}

    try:
        owner, repo, _ = parse_git_url(state["repo_url"])
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
            # Fetch repo info to get default branch + visibility
            repo_response = await client.get(f"/repos/{owner}/{repo}")
            repo_response.raise_for_status()
            repo_data = repo_response.json()
            default_branch = repo_data.get("default_branch", "main")

            # --- Public repo check ---
            if repo_data.get("private") is False:
                findings.append(
                    _finding(
                        severity="info",
                        title="Repository is public",
                        description="Repository is publicly accessible (expected for open-source projects)",
                        rule_id="github_public_repo",
                    )
                )

            # --- Branch protection check ---
            # Check for security policy first (Option C heuristic)
            has_policy = await _has_security_policy(client, owner, repo)
            has_policy_suffix = ""
            if has_policy:
                has_policy_suffix = (
                    f" (the repo has a security policy at {has_policy}, "
                    "suggesting org-level protections may exist — "
                    "a GitHub token with admin:org scope is needed "
                    "to verify)"
                )
            else:
                has_policy_suffix = (
                    " (org-level protections may not be visible "
                    "without a GitHub token with admin:org scope)"
                )

            bp_legacy = await client.get(
                f"/repos/{owner}/{repo}/branches/{default_branch}/protection"
            )
            bp_rules = await client.get(
                f"/repos/{owner}/{repo}/rules/branches/{default_branch}"
            )

            if bp_legacy.status_code == 200:
                # Legacy protection confirmed
                bp_data = bp_legacy.json()
                if not bp_data.get("required_pull_request_reviews"):
                    findings.append(
                        _finding(
                            severity="high",
                            title="Branch protection missing",
                            description=(
                                f"Default branch '{default_branch}' has no "
                                f"PR review requirements{has_policy_suffix}"
                            ),
                            rule_id="github_branch_protection",
                        )
                    )
            elif bp_rules.status_code == 200:
                rules = bp_rules.json()
                if rules and len(rules) > 0:
                    logger.info(
                        "Branch '%s' protected via %d ruleset(s)",
                        default_branch,
                        len(rules),
                    )
                else:
                    findings.append(
                        _finding(
                            severity="info",
                            title="Branch protection missing",
                            description=(
                                f"Default branch '{default_branch}' has no "
                                f"detectable protection rules{has_policy_suffix}"
                            ),
                            rule_id="github_branch_protection",
                        )
                    )
            else:
                # Neither API confirmed protection
                findings.append(
                    _finding(
                        severity="info",
                        title="Branch protection status unknown",
                        description=(
                            f"Cannot verify branch protection for "
                            f"'{default_branch}'. A GitHub token with "
                            "appropriate scope is required for accuracy."
                        ),
                        rule_id="github_branch_protection",
                    )
                )

            # --- Org-level MFA check ---
            org_response = await client.get(f"/orgs/{owner}")
            if org_response.status_code == 200:
                org_data = org_response.json()
                two_fa = org_data.get("two_factor_requirement_enabled")
                if two_fa is False:
                    findings.append(
                        _finding(
                            severity="high",
                            title="MFA not enforced",
                            description="Organization does not enforce 2FA for members",
                            rule_id="github_mfa",
                        )
                    )
                elif two_fa is None:
                    logger.info(
                        "Cannot determine org 2FA status for %s "
                        "(token lacks admin:org scope)",
                        owner,
                    )

        logger.info("GitHub API found %d findings", len(findings))
        return {"github_findings": findings}
    except Exception as exc:
        logger.error("GitHub scan failed: %s", exc)
        return {"github_findings": []}


def _finding(severity: str, title: str, description: str, rule_id: str) -> Finding:
    return {
        "tool": "github",
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": None,
        "rule_id": rule_id,
    }
