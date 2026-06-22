import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

import httpx

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Copyleft license detection
# ---------------------------------------------------------------------------

COPYLEFT_LICENSES: set[str] = {
    "gpl-2.0", "gpl-2.0-only", "gpl-2.0-or-later",
    "gpl-3.0", "gpl-3.0-only", "gpl-3.0-or-later",
    "agpl-3.0", "agpl-3.0-only", "agpl-3.0-or-later",
    "lgpl-2.0", "lgpl-2.0-only", "lgpl-2.0-or-later",
    "lgpl-2.1", "lgpl-2.1-only", "lgpl-2.1-or-later",
    "lgpl-3.0", "lgpl-3.0-only", "lgpl-3.0-or-later",
}

# Map ecosystem names in Syft CycloneDX to registry URLs
ECOSYSTEM_REGISTRY: dict[str, str] = {
    "npm": "https://registry.npmjs.org/{name}",
    "python": "https://pypi.org/pypi/{name}/json",
}

# ---------------------------------------------------------------------------
# Syft SBOM generation
# ---------------------------------------------------------------------------

async def _generate_sbom(repo_path: str) -> dict | None:
    """Run syft against repo_path and return parsed CycloneDX JSON.

    Returns None if syft is not installed or the repo has no manifests.
    """
    syft = shutil.which("syft")
    if not syft:
        logger.info("Syft not installed — SBOM/license scan requires syft. "
                     "Install from https://github.com/anchore/syft/releases")
        return None

    try:
        result = await asyncio.to_thread(
            lambda: subprocess.run(
                [syft, repo_path, "-o", "cyclonedx-json"],
                capture_output=True, text=True, timeout=120,
            )
        )
        if result.returncode != 0 or not result.stdout.strip():
            logger.info("Syft produced no output for %s (no manifests?)", repo_path)
            return None
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        logger.warning("Syft timed out for %s", repo_path)
        return None
    except json.JSONDecodeError as exc:
        logger.warning("Syft output parse failed: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Syft scan failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# SBOM parsing
# ---------------------------------------------------------------------------

def _parse_sbom_components(sbom: dict) -> list[dict]:
    """Extract dependency components from a CycloneDX JSON SBOM.

    Returns list of dicts with keys: name, version, ecosystem, licenses, is_dev.
    """
    components = []
    for comp in sbom.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        if not name or not version:
            continue

        # Determine ecosystem from purl or type
        purl = comp.get("purl", "") or ""
        ecosystem = ""
        if "pkg:npm" in purl:
            ecosystem = "npm"
        elif "pkg:pypi" in purl:
            ecosystem = "python"
        elif "pkg:gem" in purl:
            ecosystem = "rubygems"
        elif "pkg:maven" in purl:
            ecosystem = "maven"
        elif "pkg:golang" in purl:
            ecosystem = "go"
        elif "pkg:cargo" in purl:
            ecosystem = "cargo"

        # Collect licenses
        licenses = []
        for lic in comp.get("licenses", []):
            lic_id = (
                lic.get("license", {}).get("id", "")
                or lic.get("license", {}).get("name", "")
            )
            if lic_id:
                licenses.append(lic_id.lower().strip())

        # Determine if dev dependency from properties or type
        comp_type = comp.get("type", "")
        # Syft marks dev deps as "development" in the `type` field (some versions)
        is_dev = "dev" in comp_type.lower()

        components.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "licenses": licenses,
            "is_dev": is_dev,
        })

    return components


def _is_copyleft(license_id: str) -> bool:
    """Check if a normalized license ID is copyleft."""
    return license_id in COPYLEFT_LICENSES


# Regex matching platform/arch suffix for dependency dedup.
# Matches -{os}-{arch} where OS and arch are generic naming conventions,
# so any future variant (ppc64, riscv64, s390x, linuxmusl, etc.) is
# caught without updating an enumeration.
_PLATFORM_RE = re.compile(
    r"-(?:darwin|linux|linuxmusl|win32|freebsd|alpine)"
    r"-(?:arm\d?|arm64|x64|x86_64|ia32|ppc64|riscv64|s390x)$",
    re.I,
)


def _strip_platform_suffix(name: str) -> str:
    """Strip platform/arch suffix from a package name.

    '@img/sharp-libvips-linux-x64'      → '@img/sharp-libvips'
    '@img/sharp-libvips-darwin-arm64'    → '@img/sharp-libvips'
    '@img/sharp-libvips-linuxmusl-x64'  → '@img/sharp-libvips'
    'sharp-libvips-win32-ia32'          → 'sharp-libvips'
    'libvips-linux-riscv64'             → 'libvips'
    """
    return _PLATFORM_RE.sub("", name)


# ---------------------------------------------------------------------------
# Maintenance status via registry API
# ---------------------------------------------------------------------------

async def _check_maintenance(
    name: str, ecosystem: str, version: str, client: httpx.AsyncClient
) -> tuple[bool, str | None]:
    """Check if a package has had a release in the last 2 years.

    Returns (is_stale, last_publish_date_string).
    """
    url_template = ECOSYSTEM_REGISTRY.get(ecosystem)
    if not url_template:
        return False, None

    url = url_template.replace("{name}", name)
    try:
        resp = await client.get(url, timeout=15)
        if resp.status_code != 200:
            return False, None

        data = resp.json()
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - 2 * 365.25 * 86400  # ~2 years ago

        if ecosystem == "npm":
            # npm's `time` object has publish timestamps per version
            times = data.get("time", {})
            if isinstance(times, dict):
                all_versions = [v for k, v in times.items() if k != "created" and k != "modified" and v]
                if not all_versions:
                    return False, None
                # Get the latest version's publish time
                last_dates = []
                for ts in all_versions:
                    try:
                        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        last_dates.append(d)
                    except (ValueError, AttributeError):
                        continue
                if not last_dates:
                    return False, None
                latest = max(last_dates)
                last_str = latest.isoformat()[:10]
                return latest.timestamp() < cutoff, last_str
        elif ecosystem == "python":
            # PyPI's `info` has `author` and `maintainer`, releases has timestamps
            releases = data.get("releases", {})
            if not isinstance(releases, dict):
                return False, None
            all_versions = []
            for ver, files in releases.items():
                if isinstance(files, list):
                    for f in files:
                        upload_time = f.get("upload_time") if isinstance(f, dict) else None
                        if upload_time:
                            try:
                                d = datetime.fromisoformat(str(upload_time).replace("Z", "+00:00"))
                                all_versions.append(d)
                            except (ValueError, AttributeError):
                                continue
            if not all_versions:
                return False, None
            latest = max(all_versions)
            last_str = latest.isoformat()[:10]
            return latest.timestamp() < cutoff, last_str

        return False, None
    except Exception:
        return False, None


# ---------------------------------------------------------------------------
# OSV cross-reference
# ---------------------------------------------------------------------------

def _has_known_cve_in_osv(package_name: str, osv_findings: list[Finding]) -> bool:
    """Check if any OSV finding references this package."""
    pkg_lower = package_name.lower()
    for f in osv_findings:
        desc = (f.get("description") or "").lower()
        if pkg_lower in desc:
            return True
        title = (f.get("title") or "").lower()
        if pkg_lower in title:
            return True
    return False


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_sbom_license(state: AuditState) -> dict:
    """LangGraph node: generate SBOM, flag copyleft + unmaintained deps.

    Returns sbom_findings appended to state.
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"sbom_findings": []}

    # 1. Generate SBOM
    sbom = await _generate_sbom(repo_path)
    if not sbom:
        return {"sbom_findings": []}

    # 2. Parse components
    components = _parse_sbom_components(sbom)
    if not components:
        logger.info("SBOM: no components found in %s", repo_path)
        return {"sbom_findings": []}

    logger.info("SBOM: %d components found", len(components))

    # 3. Check each component
    osv_findings = state.get("osv_findings", [])
    copyleft_findings: list[Finding] = []
    # Track base package names to dedup platform-specific variants
    # (e.g. @img/sharp-libvips-linux-x64 -> @img/sharp-libvips)
    _seen_copyleft_bases: set[str] = set()
    npm_packages: list[dict] = []
    pypi_packages: list[dict] = []

    for comp in components:
        name = comp["name"]
        licenses = comp["licenses"]
        ecosystem = comp["ecosystem"]
        is_dev = comp["is_dev"]
        version = comp["version"]

        # Check for copyleft
        for lic_id in licenses:
            if _is_copyleft(lic_id):
                # Deduplicate platform-specific variants (e.g. sharp-libvips-*)
                base_name = _strip_platform_suffix(name)
                if base_name in _seen_copyleft_bases:
                    break
                _seen_copyleft_bases.add(base_name)

                # LGPL is structurally different from GPL/AGPL — it allows
                # dynamic linking into proprietary code without forcing
                # open-source. Flag it lower.
                is_lgpl = lic_id.startswith("lgpl")
                severity = "info" if is_dev or is_lgpl else "medium"
                risk = ("LGPL — check linkage model" if is_lgpl
                        else "Strong copyleft — may impose obligations")
                copyleft_findings.append({
                    "tool": "sbom",
                    "severity": severity,
                    "title": f"Copyleft license: {lic_id}",
                    "description": (
                        f"Dependency '{name}@{version}' uses {lic_id} license "
                        f"({'dev' if is_dev else 'runtime'}), "
                        f"base package '{base_name}'. {risk}"
                        f"{' (dev dependency)' if is_dev else ''}."
                    ),
                    "file_path": None,
                    "rule_id": f"sbom_copyleft_{base_name.replace('/', '_')}",
                    "finding_type": "copyleft_license_risk",
                })
                break  # one finding per dep

        # Collect packages for maintenance check
        if ecosystem == "npm":
            npm_packages.append(comp)
        elif ecosystem == "python":
            pypi_packages.append(comp)

    # 4. Check maintenance status for npm + PyPI
    unmaintained_findings: list[Finding] = []
    async with httpx.AsyncClient(timeout=15) as client:
        for pkg in npm_packages + pypi_packages:
            is_stale, last_pub = await _check_maintenance(
                pkg["name"], pkg["ecosystem"], pkg["version"], client
            )
            if is_stale:
                has_cve = _has_known_cve_in_osv(pkg["name"], osv_findings)
                if not has_cve:
                    # Stale without a CVE is noise — tiny stable packages
                    # (lodash.isboolean, ee-first, etc.) don't need updates.
                    # Cross-reference successful: osv runs first (~3s),
                    # sbom takes 30s+ fetching npm registries.
                    continue
                unmaintained_findings.append({
                    "tool": "sbom",
                    "severity": "medium",
                    "title": f"Unmaintained + CVE: {pkg['name']}",
                    "description": (
                        f"Dependency '{pkg['name']}@{pkg['version']}' has not been "
                        f"updated since {last_pub or 'unknown'} (2+ years) AND has "
                        f"one or more known CVEs. Categorically replace or update."
                    ),
                    "file_path": None,
                    "rule_id": f"sbom_unmaintained_{pkg['name'].replace('/', '_')}",
                    "finding_type": "unmaintained_dependency",
                })

    all_findings = copyleft_findings + unmaintained_findings
    logger.info(
        "SBOM+license: %d copyleft, %d unmaintained = %d total",
        len(copyleft_findings), len(unmaintained_findings), len(all_findings),
    )
    return {"sbom_findings": all_findings}
