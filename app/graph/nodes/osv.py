import asyncio
import json
import logging
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)


def _run_osv_sync(repo_path: str) -> list[Finding]:
    """Run osv-scanner synchronously in a thread."""
    osv_path = shutil.which("osv-scanner")
    if not osv_path:
        raise RuntimeError("osv-scanner is not installed or not on PATH")

    result = subprocess.run(
        [osv_path, "--format", "json", repo_path],
        capture_output=True,
        timeout=300,
    )

    stdout_str = (result.stdout.decode(errors="replace") if result.stdout else "").strip()
    stderr_str = (result.stderr.decode(errors="replace") if result.stderr else "").strip()

    # osv-scanner exits non-zero when it finds vulnerabilities.
    # If we got JSON on stdout, proceed — it found stuff.
    if not stdout_str:
        raise RuntimeError(
            stderr_str or f"osv-scanner exited with code {result.returncode} (no output)"
        )

    data = json.loads(stdout_str)

    # Group vulnerabilities by package to deduplicate noisy multi-CVE findings
    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    packages: dict[str, dict] = {}

    for scan_result in data.get("results", []):
        for pkg in scan_result.get("packages", []):
            pkg_name = (pkg.get("package") or {}).get("name") or "unknown"
            if pkg_name not in packages:
                packages[pkg_name] = {
                    "max_severity": "info",
                    "max_severity_score": 0,
                    "vulns": [],
                    "purl": (pkg.get("package") or {}).get("purl", ""),
                }

            for vuln in pkg.get("vulnerabilities", []):
                sev = _severity(vuln)
                sev_score = SEVERITY_RANK.get(sev, 0)
                if sev_score > packages[pkg_name]["max_severity_score"]:
                    packages[pkg_name]["max_severity"] = sev
                    packages[pkg_name]["max_severity_score"] = sev_score
                packages[pkg_name]["vulns"].append(vuln)

    findings: list[Finding] = []
    for pkg_name, info in packages.items():
        vulns = info["vulns"]
        if len(vulns) == 1:
            v = vulns[0]
            findings.append(
                {
                    "tool": "osv",
                    "severity": info["max_severity"],
                    "title": v["id"],
                    "description": v.get("summary", v["id"]),
                    "file_path": None,
                    "rule_id": v["id"],
                }
            )
        else:
            # Group multiple CVEs for the same package into one finding
            cve_ids = [v["id"] for v in vulns]
            summaries = [v.get("summary", "") for v in vulns if v.get("summary")]
            # Use the most descriptive summary as the "title" description
            top_cves = cve_ids[:3]
            others_count = len(cve_ids) - 3
            cve_list = ", ".join(top_cves)
            if others_count > 0:
                cve_list += f" (+{others_count} more)"

            findings.append(
                {
                    "tool": "osv",
                    "severity": info["max_severity"],
                    "title": f"{pkg_name}: {len(vulns)} known vulnerabilities",
                    "description": (
                        f"{pkg_name} has {len(vulns)} known CVEs: {cve_list}. "
                        f"{'Includes: ' + '; '.join(summaries[:2]) if summaries else ''}"
                    ),
                    "file_path": None,
                    "rule_id": f"osv_{pkg_name}",
                }
            )

    if result.returncode != 0 and stderr_str:
        logger.info(
            "osv-scanner exited %d with stderr (expected): %s",
            result.returncode,
            stderr_str[:200],
        )

    return findings


async def run_osv(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"osv_findings": [], "error": "No local_path in state"}

    try:
        findings = await asyncio.to_thread(_run_osv_sync, repo_path)
        logger.info("OSV found %d findings", len(findings))
        return {"osv_findings": findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("OSV scan failed: %s", err_text)
        return {"osv_findings": [], "error": err_text}


def _severity(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    if not severities:
        return "medium"

    score = severities[0].get("score")
    if score is None:
        return "medium"

    score_text = str(score).lower()
    for label in ("critical", "high", "medium", "low"):
        if label in score_text:
            return label

    try:
        numeric_score = float(score_text.split("/")[0])
    except ValueError:
        return "medium"

    if numeric_score >= 9:
        return "critical"
    if numeric_score >= 7:
        return "high"
    if numeric_score >= 4:
        return "medium"
    return "low"
