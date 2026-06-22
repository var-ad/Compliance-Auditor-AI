import logging
import os
import re
import yaml

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SAST tool names to look for in workflow steps
# ---------------------------------------------------------------------------

SAST_TOOLS = {
    "semgrep", "codeql", "snyk", "sonarqube", "sonarcloud", "bandit",
    "gosec", "brakeman", "checkmarx", "veracode", "fortify", "appscan",
    "trivy", "grype", "safety", "pip-audit", "npm-audit", "yarn-audit",
    "dependency-check", "owasp", "zap", "burp", "nikto",
}

# ---------------------------------------------------------------------------
# Publishing commands that should be preceded by a signing step
# ---------------------------------------------------------------------------

PUBLISH_COMMANDS = {
    "docker push", "docker/push", "npm publish", "npm-publish",
    "cargo publish", "mvn deploy", "gradle publish", "twine upload",
    "gh release create", "goreleaser",
}

SIGNING_INDICATORS = {
    "cosign", "gpg", "sign", "notary", "sigstore", "keyless",
    "npm provenance", "--provenance", "attest",
}

# ---------------------------------------------------------------------------
# Secrets patterns — values that look like credentials in workflow env:
# either known patterns (sk-..., AKIA..., etc.) or suspiciously long
# alphanumeric strings assigned directly (not via secrets context)
# ---------------------------------------------------------------------------

_SECRET_VALUE_PATTERN = re.compile(
    r"(?:sk-(?:live|test|prod)_|AKIA|ghp_|gho_|ghu_|ghs_|github_pat_"
    r"|xox[bpras]-|eyJ[a-zA-Z0-9_-]+\.eyJ)"
)

# Minimum length for an env value to be suspicious as a hardcoded secret
_MIN_SECRET_LENGTH = 20


def _find_workflow_files(repo_path: str) -> list[str]:
    """Discover workflow YAML files in .github/workflows/."""
    workflows_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []
    files = []
    for fn in os.listdir(workflows_dir):
        if fn.lower().endswith((".yml", ".yaml")):
            files.append(os.path.join(workflows_dir, fn))
    return sorted(files)


def _parse_workflow(filepath: str) -> dict | None:
    """Safely parse a workflow YAML file."""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            return yaml.safe_load(f)
    except Exception as exc:
        logger.debug("Failed to parse workflow %s: %s", filepath, exc)
        return None


def _walk_jobs(workflow: dict) -> list[dict]:
    """Walk all jobs and their steps from a parsed workflow dict."""
    steps = []
    jobs = workflow.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            # Container jobs may have `steps` or be nested
            for step in job.get("steps", []):
                if isinstance(step, dict):
                    step["_job"] = job_name
                    steps.append(step)
            # Recurse into strategy matrix jobs? Not needed — they reuse the same steps.
            # Recurse into reusable workflows? Not directly — they call a remote workflow.
    return steps


def _step_uses_tool(step: dict, tools: set) -> bool:
    """Check if a step references any of the given tools."""
    step_str = str(step).lower()
    return any(t in step_str for t in tools)


def _is_secret_ref(value: str) -> bool:
    """Check if an env value references GitHub secrets context."""
    v = value.strip()
    return v.startswith("${{ secrets.") or v.startswith("${{vars.")


def _looks_like_hardcoded_secret(value: str) -> bool:
    """Check if a string looks like a hardcoded credential."""
    if not value or not isinstance(value, str):
        return False
    if _is_secret_ref(value):
        return False
    if len(value) < _MIN_SECRET_LENGTH and not _SECRET_VALUE_PATTERN.search(value):
        return False
    # Skip common non-secret values
    if value.lower() in ("true", "false", "latest", "node", "python"):
        return False
    if value.startswith("${{"):
        return False
    return True


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_cicd_security(state: AuditState) -> dict:
    """LangGraph node: scan CI/CD workflow files for security gaps.

    Checks:
    1. Plaintext secrets in env: blocks (not using ${{ secrets.* }})
    2. Missing SAST/security scanning gates
    3. Unsigned artifact publishing
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"cicd_findings": []}

    workflow_files = _find_workflow_files(repo_path)
    if not workflow_files:
        logger.info("CI/CD scan: no workflow files found")
        return {"cicd_findings": []}

    logger.info("CI/CD scan: found %d workflow files", len(workflow_files))

    findings: list[Finding] = []
    has_sast = False
    all_steps: list[dict] = []

    for wf_path in workflow_files:
        rel_path = os.path.relpath(wf_path, repo_path).replace("\\", "/")
        wf = _parse_workflow(wf_path)
        if not wf:
            continue

        wf_name = wf.get("name", rel_path)
        steps = _walk_jobs(wf)
        all_steps.extend(steps)

        # ── 1. Hardcoded secrets in env blocks ─────────────────────────
        for step in steps:
            env = step.get("env", {})
            if not isinstance(env, dict):
                continue
            for key, value in env.items():
                if _looks_like_hardcoded_secret(str(value)):
                    findings.append({
                        "tool": "cicd",
                        "severity": "critical",
                        "title": f"Plaintext secret in env: {key}",
                        "description": (
                            f"Workflow '{wf_name}' step sets env var "
                            f"'{key}' to a hardcoded value. "
                            f"Use ${{{{ secrets.{key} }}}} instead of "
                            f"embedding the value directly in the YAML."
                        ),
                        "file_path": rel_path,
                        "rule_id": f"cicd_secret_{key.lower()}",
                        "finding_type": "cicd_plaintext_secret",
                    })

            # Also check run: blocks for inline secret patterns
            run = step.get("run", "")
            if isinstance(run, str):
                for m in _SECRET_VALUE_PATTERN.finditer(run):
                    findings.append({
                        "tool": "cicd",
                        "severity": "critical",
                        "title": "Plaintext secret in run step",
                        "description": (
                            f"Workflow '{wf_name}' has a hardcoded secret "
                            f"pattern in a run: block ({m.group()[:12]}...). "
                            f"Use ${{{{ secrets.NAME }}}} instead."
                        ),
                        "file_path": rel_path,
                        "rule_id": "cicd_secret_in_run",
                        "finding_type": "cicd_plaintext_secret",
                    })

        # ── 2. Check for SAST tool presence ───────────────────────────
        if _workflow_has_sast(steps):
            has_sast = True

        # ── 3. Unsigned artifact publishing ────────────────────────────
        pubs = _detect_unsigned_publishing(steps, wf_name, rel_path)
        findings.extend(pubs)

    # ── 2 (cont). If workflows exist but no SAST found ────────────────
    if workflow_files and not has_sast:
        findings.append({
            "tool": "cicd",
            "severity": "low",
            "title": "No SAST gate in CI/CD",
            "description": (
                f"None of the {len(workflow_files)} workflow files in "
                "this repository include a SAST or security scanning step. "
                "Consider adding CodeQL, Semgrep, or Snyk to pull request "
                "workflows."
            ),
            "file_path": None,
            "rule_id": "cicd_missing_sast_gate",
            "finding_type": "missing_sast_gate",
        })

    logger.info("CI/CD scan: %d findings from %d workflows",
                 len(findings), len(workflow_files))
    return {"cicd_findings": findings}


def _workflow_has_sast(steps: list[dict]) -> bool:
    """Check if any step in a workflow references a SAST tool."""
    for step in steps:
        if _step_uses_tool(step, SAST_TOOLS):
            return True
    return False


def _detect_unsigned_publishing(
    steps: list[dict], wf_name: str, rel_path: str
) -> list[Finding]:
    """Detect publish commands without a preceding signing step."""
    findings: list[Finding] = []
    had_sign = False

    for step in steps:
        run = (step.get("run", "") or "")
        uses = (step.get("uses", "") or "")
        combined = (run + " " + uses).lower()

        # Check if this step is a signing step
        if any(s in combined for s in SIGNING_INDICATORS):
            had_sign = True
            continue

        # Check if this step is a publish step
        is_publish = any(cmd in combined for cmd in PUBLISH_COMMANDS)
        if is_publish and not had_sign:
            findings.append({
                "tool": "cicd",
                "severity": "medium",
                "title": "Unsigned artifact publish",
                "description": (
                    f"Workflow '{wf_name}' publishes artifacts without a "
                    f"preceding signing step (cosign, GPG, provenance). "
                    f"Consumers cannot verify the integrity of the artifact."
                ),
                "file_path": rel_path,
                "rule_id": "cicd_unsigned_publish",
                "finding_type": "unsigned_artifact_publish",
            })
            # Reset signing tracker after each publish
            had_sign = False

    return findings
