import logging
import re

from app.graph.state import AuditState, Finding, MappedControl

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
from app.mapper.controls import (
    GDPR_DPDP_EXCLUDED_TYPES,
    REMEDIATION_MAP,
    _batch_classify_cves,
    _classify_cve,
    _classify_finding_type,
    batch_map_findings_soc2_iso,
    get_controls,
)
from app.mapper.rag_mapper import enrich_gdpr_dpdp_explanations
from app.utils.config import GROQ_API_KEY, LLM_MODEL
from groq import AsyncGroq

logger = logging.getLogger(__name__)

# Curated GDPR/DPDP mapping: every security finding category maps to the
# CORRECT security provisions. No LLM free-association — this table is the
# source of truth for which control applies. Each entry includes a specific
# explanation tailored to that vulnerability type.
CURATED_GDPR_DPDP: list[dict] = [
    # SQL injection / data access — directly exposes personal data in databases
    {
        "keywords": ("sql", "sqli", "injection", "database", "query"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "SQL injection can expose personal data stored in databases by bypassing "
                "application-level access controls. This violates GDPR Art. 32(1)(a) which "
                "requires appropriate technical measures to ensure ongoing confidentiality "
                "and integrity of processing systems."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Unvalidated SQL queries risk unauthorized access to personal data, violating "
                "DPDP Rule 8(1) which requires reasonable security safeguards to prevent "
                "personal data breaches."
            ),
        },
    },
    # Secrets / credentials / JWT — keys used to access personal data
    {
        "keywords": ("secret", "hardcoded", "jwt", "credential", "password", "token", "key"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Hardcoded credentials in source code bypass access controls and can expose "
                "personal data if a repository is compromised. This violates GDPR Art. 32(1)(b)'s "
                "requirement to ensure the ongoing confidentiality of processing systems."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Embedded secrets in source code create a risk of unauthorized data access, "
                "violating DPDP Rule 8's requirement for technical safeguards to protect "
                "personal data throughout its lifecycle."
            ),
        },
    },
    # Path traversal / file access — can read files with personal data
    {
        "keywords": ("path traversal", "ssrf", "file path", "directory", "file access"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Path traversal vulnerabilities allow attackers to read arbitrary files, "
                "potentially exposing personal data stored on the server. This violates "
                "GDPR Art. 32(1)(d)'s requirement for processes to regularly test and "
                "evaluate the effectiveness of security measures."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Unrestricted file access can lead to unauthorized disclosure of personal data, "
                "violating DPDP Rule 8's requirement for security safeguards that prevent "
                "unauthorized access to data."
            ),
        },
    },
    # XSS / CSRF / request forgery — steals user data from sessions
    {
        "keywords": ("xss", "csrf", "cross-site", "cross site", "request forgery"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Cross-site scripting allows attackers to execute code in users' browsers, "
                "potentially stealing session tokens and accessing personal data. This violates "
                "GDPR Art. 32(1)(a)'s obligation to implement measures protecting against "
                "unauthorized processing."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "XSS vulnerabilities can expose users' personal data to attackers, violating "
                "DPDP Rule 8's requirement for reasonable security safeguards, including "
                "protection against common web application attacks."
            ),
        },
    },
    # Crypto / TLS / SSL / weak RNG — encryption directly protects personal data
    {
        "keywords": ("crypto", "tls", "ssl", "md5", "sha1", "random", "encryption"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Weak cryptographic algorithms (MD5, SHA1) or non-cryptographic random "
                "number generators undermine data protection measures. This violates GDPR "
                "Art. 32(1)(a) which requires pseudonymisation and encryption of personal data "
                "using state-of-the-art methods."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Use of weak cryptography can lead to data exposure, violating DPDP Rule 8's "
                "requirement for appropriate technical safeguards including encryption "
                "standards for protecting personal data."
            ),
        },
    },
    # Deserialization / RCE — full system access can read all data
    # NOTE: avoid short keywords like "rce" that cause false matches
    # (e.g. "rce" is a substring of "source" in finding descriptions)
    {
        "keywords": ("deserialization", "code execution", "objectinputstream", "remote code"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Unsafe deserialization can lead to remote code execution, giving attackers "
                "full access to processing systems. This violates GDPR Art. 32(1)(b)'s "
                "requirement for ensuring the ongoing confidentiality, integrity, and "
                "resilience of processing systems."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Remote code execution vulnerabilities compromise the entire data processing "
                "environment, violating DPDP Rule 8's requirement to implement safeguards "
                "that prevent unauthorized access to personal data."
            ),
        },
    },
    # Cookie / session / auth — session data includes user personal data
    {
        "keywords": ("cookie", "session", "httponly", "secure flag", "authentication"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Insecure cookie flags (missing HttpOnly or Secure) allow session hijacking "
                "via XSS or network eavesdropping. This violates GDPR Art. 32(1)(a) which "
                "requires encryption and confidentiality measures for personal data in transit."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Insecure session management can expose user sessions to hijacking, violating "
                "DPDP Rule 8's requirement to implement security safeguards that protect "
                "personal data during processing and transmission."
            ),
        },
    },
    # Open redirect / URL injection — phishing can steal personal data
    {
        "keywords": ("redirect", "open redirect", "url injection"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Open redirect vulnerabilities can be used in phishing attacks to trick users "
                "into revealing credentials or personal data. This violates GDPR Art. 32(1)(c)'s "
                "requirement for ensuring the ongoing resilience of processing systems."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Open redirects create phishing risks that can lead to personal data exposure, "
                "violating DPDP Rule 8's requirement for safeguards against social engineering "
                "and deception-based attacks."
            ),
        },
    },
    # Dependency / CVE / vulnerability — ambiguous but safer to flag
    # (some CVEs affect data-touching libraries like xstream, sql drivers)
    {
        "keywords": ("cve", "known vulnerability", "dependency", "xstream", "cpe"),
        "personal_data": True,
        "gdpr": {
            "control_id": "gdpr_article_32",
            "control_name": "Security of Processing",
            "explanation": (
                "Known vulnerabilities in third-party dependencies are unpatched security gaps "
                "that attackers can exploit to access personal data. This violates GDPR Art. 32(1)(d)'s "
                "requirement for regular testing and evaluation of security measures."
            ),
        },
        "dpdp": {
            "control_id": "dpdp_rule_8",
            "control_name": "Security Safeguards",
            "explanation": (
                "Unpatched dependency vulnerabilities create exploitable attack vectors for "
                "data breaches, violating DPDP Rule 8's requirement for ongoing security "
                "safeguards including vulnerability management."
            ),
        },
    },
    # MFA / branch protection / public repo (org-level) — INFRASTRUCTURE
    # These are dev-process and access management concerns, not data protection.
    # They map to SOC2/ISO through controls.py but should NOT trigger GDPR/DPDP.
    {
        "keywords": ("mfa", "2fa", "branch protection", "public repository"),
        "personal_data": False,
    },
    # Docker / container / root — INFRASTRUCTURE (config, no personal data)
    {
        "keywords": ("docker", "container", "root"),
        "personal_data": False,
    },
]


def _curated_gdpr_dpdp(findings: list[Finding]) -> list[MappedControl]:
    """Primary GDPR/DPDP mapping.

    Source of truth for WHETHER a finding gets GDPR/DPDP comes from
    controls.py's CONTROL_MAP (via get_controls()). The curated table
    in this file only provides explanation text — the control selection
    is driven by the canonical map.

    For findings not in the curated table, a generic explanation is used.
    """
    mapped: list[MappedControl] = []
    seen: set[str] = set()  # rule_ids handled by curated table

    # First pass: curated table for specific explanations
    for finding in findings:
        rid = finding.get("rule_id") or ""
        desc = (finding.get("description") or "").lower()
        title = (finding.get("title") or "").lower()

        # Hard skip: known governance rule_ids — handled by controls.py
        if rid in ("github_branch_protection", "github_public_repo", "github_mfa"):
            seen.add(rid)
            continue

        # Skip curated table for pre-classified findings (e.g. CVE subtypes).
        # The CVE LLM classifier is more accurate than keyword matching,
        # so let the second pass handle these via get_controls() instead.
        if finding.get("finding_type"):
            continue

        for entry in CURATED_GDPR_DPDP:
            if any(kw in desc or kw in title for kw in entry["keywords"]):
                seen.add(rid)
                if not entry.get("personal_data", True):
                    break  # infra finding, no GDPR/DPDP

                gdpr_info = entry.get("gdpr")
                dpdp_info = entry.get("dpdp")
                if gdpr_info:
                    mapped.append({
                        "finding": finding,
                        "framework": "gdpr",
                        "control_id": gdpr_info["control_id"],
                        "control_name": gdpr_info["control_name"],
                        "explanation": gdpr_info["explanation"],
                    })
                if dpdp_info:
                    mapped.append({
                        "finding": finding,
                        "framework": "dpdp",
                        "control_id": dpdp_info["control_id"],
                        "control_name": dpdp_info["control_name"],
                        "explanation": dpdp_info["explanation"],
                    })
                break  # first match per finding

    # Second pass: unmatched findings — check canonical CONTROL_MAP
    for finding in findings:
        rid = finding.get("rule_id") or ""
        if rid in seen:
            continue

        preclass = finding.get("finding_type")
        controls = get_controls(rid, finding.get("description", ""), preclass)

        # Hard exclusion: known governance/infra types never get GDPR/DPDP
        from app.mapper.controls import _classify_finding_type  # noqa: PLC0415
        if _classify_finding_type(rid, finding.get("description", ""), preclass) in GDPR_DPDP_EXCLUDED_TYPES:
            continue

        gdpr_controls = [c for c in controls if c["framework"] == "gdpr"]
        dpdp_controls = [c for c in controls if c["framework"] == "dpdp"]

        if gdpr_controls:
            gc = gdpr_controls[0]
            mapped.append({
                "finding": finding,
                "framework": "gdpr",
                "control_id": gc["control_id"],
                "control_name": gc["control_name"],
                "explanation": (
                    f"Finding '{finding.get('title', '')}' relates to "
                    f"{gc['control_name']} ({gc['control_id']}) as it involves "
                    f"processing of personal data."
                ),
            })
        if dpdp_controls:
            dc = dpdp_controls[0]
            mapped.append({
                "finding": finding,
                "framework": "dpdp",
                "control_id": dc["control_id"],
                "control_name": dc["control_name"],
                "explanation": (
                    f"Finding '{finding.get('title', '')}' relates to "
                    f"{dc['control_name']} ({dc['control_id']}) as it involves "
                    f"processing of personal data."
                ),
            })

    return mapped


async def _preclassify_cve_findings(findings: list[Finding]) -> None:
    """Run LLM classifier on OSV findings to determine CVE subtype.

    Uses a single batched API call for all CVEs instead of one call per CVE.
    Sets finding["finding_type"] on each OSV finding in-place.
    Failures fall back to heuristic classification in controls.py.
    """
    osv_findings = [f for f in findings if f.get("tool") == "osv"]
    if not osv_findings:
        return

    # Collect descriptions for batch classification
    items: list[tuple[str, str]] = []
    for f in osv_findings:
        desc = f.get("description", "")
        rid = str(f.get("rule_id", ""))
        if desc and rid:
            items.append((desc, rid))

    if not items:
        return

    client = AsyncGroq(api_key=GROQ_API_KEY)
    try:
        results = await _batch_classify_cves(items, client)
        for finding in osv_findings:
            rid = str(finding.get("rule_id", ""))
            ftype = results.get(rid, "")
            if ftype:
                finding["finding_type"] = ftype
                logger.info("CVE: %s -> %s", rid, ftype)
    except Exception as exc:
        logger.info("Batch CVE classify failed (%s), falling back to per-CVE", exc)
        # Fallback: individual calls
        for finding in osv_findings:
            description = finding.get("description", "")
            if not description:
                continue
            try:
                result = await _classify_cve(description, client)
                finding["finding_type"] = result
                logger.info("CVE: %s -> %s", finding.get("rule_id"), result)
            except Exception as exc2:
                logger.info("CVE: %s failed (%s), using heuristic",
                            finding.get("rule_id"), exc2)


async def run_compliance_mapper(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    try:
        # Collect and validate all findings from scanner nodes
        raw_findings = []
        findings_sources = [
            ("semgrep", *state.get("semgrep_findings", [])),
            ("osv", *state.get("osv_findings", [])),
            ("github", *state.get("github_findings", [])),
            ("secrets", *state.get("secrets_findings", [])),
            ("governance", *state.get("governance_findings", [])),
            ("sbom", *state.get("sbom_findings", [])),
            ("iac", *state.get("iac_findings", [])),
            ("cicd", *state.get("cicd_findings", [])),
            ("data_class", *state.get("data_classification_findings", [])),
        ]
        for source, *items in findings_sources:
            for item in items:
                if not isinstance(item, dict):
                    logger.warning("Mapper: %s finding is not a dict: %s (type=%s)",
                                   source, item, type(item).__name__)
                    continue
                raw_findings.append(item)

        # Strip local temp path prefix from all file_path values
        local_path = state.get("local_path") or ""
        _strip_path_prefix(raw_findings, local_path)

        deduplicated_findings = await _deduplicate_by_rule_id(raw_findings)

        # Step 0: Pre-classify CVE findings using LLM (sets finding_type hint)
        await _preclassify_cve_findings(deduplicated_findings)
        logger.info("Step 0 done: %d deduplicated findings", len(deduplicated_findings))

        # Step 0b: Enrich findings with remediation text from REMEDIATION_MAP.
        # Each finding's remediation is determined by its finding_type (which
        # the classifier sets). Findings not covered by the map get None.
        for f in deduplicated_findings:
            if f.get("remediation"):
                continue
            ftype = f.get("finding_type")
            if not ftype:
                desc = f.get("description", "")
                rid = f.get("rule_id", "")
                ftype = _classify_finding_type(rid, desc, None)
            if ftype in REMEDIATION_MAP:
                f["remediation"] = REMEDIATION_MAP[ftype]

        # Step 1: SOC2/ISO mapping (uses LLM batch with controls.py)
        soc2_iso_mapped = await batch_map_findings_soc2_iso(deduplicated_findings)
        logger.info("Step 1 done: %d SOC2/ISO mapped controls", len(soc2_iso_mapped))

        # Step 2: Curated GDPR/DPDP mapping (deterministic, always runs)
        gdpr_dpdp_mapped = _curated_gdpr_dpdp(deduplicated_findings)
        logger.info("Step 2 done: %d GDPR/DPDP controls", len(gdpr_dpdp_mapped))

        # Log finding types for debugging.
        # The raw finding_type field is the scanner-set value (None for Semgrep/GitHub).
        # The resolved type comes from _classify_finding_type() which runs during mapping.
        for f in deduplicated_findings:
            if not isinstance(f, dict):
                continue
            rid = f.get("rule_id", "")
            raw_type = f.get("finding_type")
            raw_label = raw_type or "unset"
            resolved = _classify_finding_type(rid, f.get("description", ""), raw_type)
            has_gdpr = any(
                isinstance(m, dict) and m.get("finding", {}).get("rule_id") == rid
                and m.get("framework") == "gdpr"
                for m in gdpr_dpdp_mapped
            )
            logger.info("  %s -> raw=%s resolved=%s GDPR=%s", rid, raw_label, resolved, has_gdpr)

        # Step 3: RAG enrichment
        if gdpr_dpdp_mapped:
            try:
                enriched = await enrich_gdpr_dpdp_explanations(
                    gdpr_dpdp_mapped, deduplicated_findings
                )
                if enriched:
                    gdpr_dpdp_mapped = enriched
                    logger.info("Step 3: RAG enriched %d explanations", len(enriched))
            except Exception as exc:
                logger.debug(
                    "RAG enrichment failed, keeping curated explanations: %s", exc
                )

        mapped_controls: list[MappedControl] = [
            *soc2_iso_mapped,
            *gdpr_dpdp_mapped,
        ]

        logger.info("Mapped %d controls total", len(mapped_controls))
        return {"mapped_controls": mapped_controls}
    except Exception as exc:
        logger.error("Compliance mapping failed: %s", exc)
        return {"mapped_controls": [], "error": str(exc)}


def _strip_path_prefix(findings: list[Finding], local_path: str) -> None:
    """Strip local temp path prefix from all finding file_paths in-place.

    Turns 'C:\\Users\\...\\tmpXXXX\\Dockerfile' into 'Dockerfile'
    and 'C:\\Users\\...\\tmpXXXX\\src\\db\\prisma.ts' into 'src/db/prisma.ts'.
    Handles Windows backslashes too.
    """
    if not local_path:
        return
    # Normalize: strip trailing slash, then prepend as prefix to match
    prefix = local_path.rstrip("/\\").replace("\\", "/") + "/"
    for finding in findings:
        fp = finding.get("file_path")
        if not fp or not isinstance(fp, str):
            continue
        normalized = fp.replace("\\", "/")
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]

        # Strip Linux and Windows temp clone prefixes even when local_path was
        # not an exact string match for the scanner output.
        normalized = re.sub(r"^/tmp/tmp[^/]+/", "", normalized)
        normalized = re.sub(r"^.*?[/\\]Temp[/\\]tmp[^/\\]+[/\\]", "", normalized)
        stripped = normalized.lstrip("/")

        if stripped != fp:
            finding["file_path"] = stripped
            logger.debug("Stripped path: %s -> %s", fp, finding["file_path"])


async def _deduplicate_by_rule_id(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by rule_id, keeping the most severe entry.

    Filters out any non-dict items (defensive — catches malformed scanner output).
    """
    deduplicated: dict[str, Finding] = {}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            logger.warning("Dedup: skipping non-dict finding at index %d: %s (type=%s)",
                           index, finding, type(finding).__name__)
            continue
        rule_id = finding.get("rule_id") or f"finding_{index}"
        existing = deduplicated.get(rule_id)
        if existing is None:
            deduplicated[rule_id] = finding
        else:
            curr_rank = SEVERITY_RANK.get(finding.get("severity", "low"), 0)
            exist_rank = SEVERITY_RANK.get(existing.get("severity", "low"), 0)
            if curr_rank > exist_rank:
                deduplicated[rule_id] = finding
    return list(deduplicated.values())
