import asyncio
import json
import logging
import os
import re
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IaC file detection patterns
# ---------------------------------------------------------------------------

_TF_PATTERN = re.compile(r"\.tf(\.json)?$", re.I)
_CFN_PATTERN = re.compile(
    r"(cloudformation|template)[/\\]|AWSTemplateFormatVersion"
)
_K8S_KINDS = {"Deployment", "Service", "Pod", "ConfigMap", "Secret",
              "Ingress", "Namespace", "ServiceAccount", "ClusterRole",
              "RoleBinding", "DaemonSet", "StatefulSet", "CronJob", "Job"}
_K8S_PATTERN = re.compile(
    r'^apiVersion:\s*|^kind:\s*(?:' + '|'.join(_K8S_KINDS) + r')\s*$',
    re.MULTILINE,
)

def _has_iac_files(repo_path: str) -> list[str]:
    """Scan repo for IaC files. Returns list of detected framework names.

    Returns empty list if no IaC files found.
    """
    detected: list[str] = []

    if not os.path.isdir(repo_path):
        return detected

    for root, _dirs, files in os.walk(repo_path):
        # Skip vendor/venv/node_modules
        rel = os.path.relpath(root, repo_path).replace("\\", "/")
        if any(skip in rel.split("/") for skip in
               ("node_modules", ".venv", "venv", "vendor", ".git", "__pycache__")):
            continue

        for fn in files:
            fpath = os.path.join(root, fn)

            # Terraform
            if _TF_PATTERN.search(fn):
                if "Terraform" not in detected:
                    detected.append("Terraform")
                continue

            # CloudFormation
            if fn.lower().endswith((".yaml", ".yml")):
                if _CFN_PATTERN.search(rel + "/" + fn):
                    if "CloudFormation" not in detected:
                        detected.append("CloudFormation")
                    continue

                # Kubernetes — read first few lines looking for apiVersion + kind
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as fh:
                        head = fh.read(2048)
                    if _K8S_PATTERN.search(head):
                        if "Kubernetes" not in detected:
                            detected.append("Kubernetes")
                        continue
                except Exception:
                    pass

            # Dockerfile (detection only — semgrep handles scanning)
            if fn.upper() == "DOCKERFILE" or fn.startswith("Dockerfile"):
                if "Dockerfile" not in detected:
                    detected.append("Dockerfile")

    return sorted(detected)


# ---------------------------------------------------------------------------
# Checkov scanner
# ---------------------------------------------------------------------------

_CHECKOV_CHECK_RE = re.compile(r"CKV_\w+_\d+")


def _parse_checkov_output(checkov_json: str) -> list[dict]:
    """Parse Checkov JSON output into flat finding dictionaries.

    Returns list of dicts with keys: check_id, check_name, severity,
    file_path, guideline, resource, category.
    """
    results: list[dict] = []
    try:
        data = json.loads(checkov_json)
    except json.JSONDecodeError as exc:
        logger.warning("Checkov JSON parse failed: %s", exc)
        return results

    # A single framework returns a dict. Multiple frameworks return a list of
    # those dicts, so flatten every failed_checks collection before mapping.
    failed_checks: list[dict] = []
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        if not isinstance(report, dict):
            continue
        report_results = report.get("results", {})
        if isinstance(report_results, dict):
            checks = report_results.get("failed_checks", [])
        elif isinstance(report_results, list):
            checks = report_results
        else:
            checks = report.get("failed_checks", [])
        if isinstance(checks, list):
            failed_checks.extend(check for check in checks if isinstance(check, dict))

    for check in failed_checks:
        check_id = str(check.get("check_id") or "")
        check_name = str(check.get("check_name") or "")
        severity = _map_checkov_severity(
            check.get("severity"),
            check_id,
        )
        file_path = str(
            check.get("repo_file_path") or check.get("file_path") or ""
        )
        guideline = str(check.get("guideline") or "")
        resource = str(check.get("resource") or "")

        results.append({
            "check_id": check_id,
            "check_name": check_name,
            "severity": severity,
            "file_path": file_path,
            "guideline": guideline,
            "resource": resource,
        })

    return results


def _map_checkov_severity(severity: str | None, check_id: str) -> str:
    """Map Checkov severity to our 4-tier system."""
    sev = str(severity or "").lower()
    if sev in ("critical", "high"):
        return "high"
    if sev in ("medium", "moderate"):
        return "medium"
    if sev == "low":
        return "low"
    return "medium"


def _classify_checkov_check(check_id: str, check_name: str) -> str:
    """Map a Checkov check to a finding_type key in CONTROL_MAP."""
    cid = str(check_id or "").lower()
    cname = str(check_name or "").lower()

    # Dockerfile hardening. Keep these ahead of the generic IaC buckets so
    # Docker checks do not inherit S3/storage remediations.
    if "docker" in cid:
        if "healthcheck" in cname or cid.endswith("_2"):
            return "iac_docker_healthcheck"
        if "user" in cname or "root" in cname or cid.endswith("_3"):
            return "iac_docker_user"

    # Storage misconfiguration (S3 bucket, public access, etc.)
    if "s3" in cid and any(w in cname for w in ("public", "acl", "policy", "versioning", "encryption")):
        return "iac_storage_misconfigured"
    if "google_storage_bucket" in cid and "public" in cname:
        return "iac_storage_misconfigured"
    if "s3" in cid and "log" in cname:
        return "iac_logging_missing"

    # Network exposure (open security groups, public IPs)
    if any(w in cid for w in ("sg", "security_group", "network", "cidr")):
        if "0.0.0.0" in cname or "any" in cname or "open" in cname or "public" in cname:
            return "iac_network_exposed"
    if "eks" in cid and "public" in cname:
        return "iac_network_exposed"
    if "google_compute_firewall" in cid and "open" in cname:
        return "iac_network_exposed"

    # Encryption
    if any(w in cid for w in ("encrypt", "kms", "key")):
        return "iac_encryption_missing"
    if "ssl" in cid or "tls" in cid:
        return "iac_encryption_missing"

    # Logging / monitoring
    if any(w in cid for w in ("log", "cloudtrail", "monitor", "audit")):
        return "iac_logging_missing"

    # Default: storage misconfiguration (broadest bucket)
    return "iac_storage_misconfigured"


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_iac_config(state: AuditState) -> dict:
    """LangGraph node: scan IaC configs with Checkov.

    1. Detects whether the repo has any IaC files.
    2. If none found, returns iac_scan_skipped=True + empty findings.
    3. If present, runs Checkov and maps results to finding types.
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"iac_findings": [], "iac_scan_skipped": False}

    # Step 1: Detect IaC files
    frameworks = _has_iac_files(repo_path)
    if not frameworks:
        logger.info("IaC scan: no IaC files found — skipping")
        return {"iac_findings": [], "iac_scan_skipped": True}

    logger.info("IaC scan: detected %s", frameworks)

    # Step 2: Run Checkov
    checkov = shutil.which("checkov")
    if not checkov:
        logger.info("Checkov not installed — install from pip (pip install checkov)")
        # If Checkov isn't available, we can still report which IaC was found
        # as informational findings
        info_findings: list[Finding] = []
        for fw in frameworks:
            if fw == "Dockerfile":
                continue  # handled by semgrep already
            info_findings.append({
                "tool": "iac",
                "severity": "info",
                "title": f"IaC detected: {fw}",
                "description": (
                    f"IaC framework '{fw}' detected in repository. "
                    "Install checkov (pip install checkov) to enable "
                    "configuration scanning."
                ),
                "file_path": None,
                "rule_id": f"checkov_missing_{fw.lower()}",
                "finding_type": "iac_storage_misconfigured",
            })
        return {"iac_findings": info_findings, "iac_scan_skipped": False}

    try:
        result = await asyncio.to_thread(
            lambda: subprocess.run(
                [checkov, "-d", repo_path, "-o", "json", "--compact"],
                capture_output=True, text=True, timeout=300,
            )
        )
    except subprocess.TimeoutExpired:
        logger.warning("Checkov timed out for %s", repo_path)
        return {"iac_findings": [], "iac_scan_skipped": False}
    except FileNotFoundError:
        logger.warning("Checkov binary not found at %s", checkov)
        return {"iac_findings": [], "iac_scan_skipped": False}
    except Exception as exc:
        logger.warning("Checkov scan failed: %s", exc)
        return {"iac_findings": [], "iac_scan_skipped": False}

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    logger.info(
        "Checkov rc=%s stdout_len=%s stderr_len=%s",
        result.returncode,
        len(stdout),
        len(stderr),
    )
    if stdout:
        logger.debug("Checkov stdout preview: %s", stdout[:1000])
    if stderr:
        logger.debug("Checkov stderr preview: %s", stderr[:1000])

    # Checkov exits 1 when checks fail (findings exist), 0 when all pass.
    if result.returncode not in (0, 1):
        logger.warning(
            "Checkov failed with exit code %s: %s",
            result.returncode,
            stderr[:1000],
        )
        return {"iac_findings": [], "iac_scan_skipped": False}

    if not stdout.strip():
        logger.info("Checkov produced no JSON output for %s", repo_path)
        return {"iac_findings": [], "iac_scan_skipped": False}

    # Step 3: Parse and map findings
    parsed = _parse_checkov_output(stdout)
    findings: list[Finding] = []

    for item in parsed:
        check_id = item["check_id"]
        check_name = item["check_name"]
        severity = item["severity"]
        file_path = item["file_path"]
        guideline = item["guideline"]
        resource = item["resource"]
        finding_type = _classify_checkov_check(check_id, check_name)

        # Escalate some severities based on finding type
        if "public" in check_name.lower() and "bucket" in check_name.lower():
            severity = "high"
        if "0.0.0.0" in check_name:
            severity = "high"

        findings.append({
            "tool": "iac",
            "severity": severity,
            "title": f"IaC: {check_id}",
            "description": (
                f"{check_name} — {resource} "
                f"(in {file_path}). "
                f"Guideline: {guideline or 'N/A'}"
            ),
            "file_path": file_path,
            "rule_id": f"checkov_{check_id}",
            "finding_type": finding_type,
        })

    logger.info("IaC scan: %d Checkov findings across %s",
                 len(findings), frameworks)
    return {"iac_findings": findings, "iac_scan_skipped": False}
