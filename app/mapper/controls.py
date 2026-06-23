import json
import logging
import re

from groq import AsyncGroq

from app.graph.state import Finding, MappedControl
from app.utils.config import GROQ_API_KEY, LLM_MODEL
from app.utils.llm import groq_retry, strip_markdown_fences

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DETERMINISTIC CONTROL MAPPING TABLE
# LLM is restricted to writing explanations only — never chooses controls.
# Format per entry: "finding_type": ["FW:ctrl_id", ...]
# ---------------------------------------------------------------------------

# framework prefix → canonical framework string
_FW = {
    "SOC2": "soc2",
    "ISO": "iso27001",
    "GDPR": "gdpr",
    "DPDP": "dpdp",
}

# Mapping from finding-type key to control entries.
# Built from RAW_CONTROL_MAP at module load time.
CONTROL_MAP: dict[str, list[dict]] = {}

RAW_CONTROL_MAP: dict[str, list[str]] = {
    # ------------------------------------------------------------------ #
    # CONTAINER & INFRASTRUCTURE                                         #
    # ------------------------------------------------------------------ #
    "docker_root": ["SOC2:CC6.1", "ISO:A.9.2.3"],
    "docker_secret_exposed": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    "docker_unverified_image": ["SOC2:CC7.1", "ISO:A.12.5.1"],
    "docker_no_resource_limits": ["SOC2:CC7.2", "ISO:A.12.1.3"],
    "docker_privileged_mode": ["SOC2:CC6.1", "ISO:A.9.2.3"],
    "iac_docker_healthcheck": ["SOC2:CC7.2", "ISO:A.12.1.3"],
    "iac_docker_user": ["SOC2:CC6.1", "ISO:A.9.2.3"],
    # ------------------------------------------------------------------ #
    # SECRETS & CREDENTIALS                                              #
    # ------------------------------------------------------------------ #
    "hardcoded_secret": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    "jwt_exposed": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    "private_key_exposed": ["SOC2:CC6.1", "ISO:A.10.1.2", "GDPR:Art. 32", "DPDP:Rule 8"],
    "cloud_credentials_exposed": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    # ------------------------------------------------------------------ #
    # CRYPTOGRAPHY                                                       #
    # ------------------------------------------------------------------ #
    "tls_disabled": ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "weak_hash": ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "weak_rng": ["SOC2:CC6.7", "ISO:A.10.1.1"],
    "hardcoded_crypto_key": ["SOC2:CC6.7", "ISO:A.10.1.2", "GDPR:Art. 32", "DPDP:Rule 8"],
    "weak_cipher": ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "missing_sri": ["SOC2:CC7.1", "ISO:A.12.5.1"],
    # ------------------------------------------------------------------ #
    # INJECTION                                                          #
    # ------------------------------------------------------------------ #
    "sql_injection": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    "sql_injection_format": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    "command_injection": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "ldap_injection": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    "xss": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "template_injection": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "log_injection": ["SOC2:CC7.2", "ISO:A.12.4.1"],
    # ------------------------------------------------------------------ #
    # ACCESS CONTROL & SESSION                                           #
    # ------------------------------------------------------------------ #
    "csrf_missing": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "open_redirect": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "trust_boundary_violation": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "missing_authn": ["SOC2:CC6.1", "ISO:A.9.4.1"],
    "broken_authz": ["SOC2:CC6.3", "ISO:A.9.4.1"],
    # ------------------------------------------------------------------ #
    # COOKIES & TRANSPORT                                                #
    # ------------------------------------------------------------------ #
    "cookie_missing_httponly": ["SOC2:CC6.7", "ISO:A.14.2.5"],
    "cookie_missing_secure": ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "cookie_missing_samesite": ["SOC2:CC6.7", "ISO:A.14.2.5"],
    "plaintext_http": ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    # ------------------------------------------------------------------ #
    # FILE & PATH                                                        #
    # ------------------------------------------------------------------ #
    "path_traversal": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    "file_inclusion": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    "unrestricted_file_upload": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    # ------------------------------------------------------------------ #
    # SSRF                                                               #
    # ------------------------------------------------------------------ #
    "ssrf": ["SOC2:CC6.6", "ISO:A.14.2.5", "GDPR:Art. 32", "DPDP:Rule 8"],
    # ------------------------------------------------------------------ #
    # DESERIALIZATION                                                    #
    # ------------------------------------------------------------------ #
    "unsafe_deserialization": ["SOC2:CC7.1", "ISO:A.12.6.1"],
    "prototype_pollution": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    # ------------------------------------------------------------------ #
    # DENIAL OF SERVICE                                                  #
    # ------------------------------------------------------------------ #
    "redos": ["SOC2:CC7.2", "ISO:A.12.1.3"],
    "resource_exhaustion_dos": ["SOC2:CC7.2", "ISO:A.12.1.3"],
    # ------------------------------------------------------------------ #
    # DEPENDENCY VULNERABILITIES                                         #
    # ------------------------------------------------------------------ #
    "dependency_cve_dos": ["SOC2:CC7.1", "ISO:A.12.6.1"],
    "dependency_cve_network": ["SOC2:CC7.1", "ISO:A.12.6.1"],
    "dependency_cve_data": ["SOC2:CC7.1", "ISO:A.12.6.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "dependency_cve_email": ["SOC2:CC7.1", "ISO:A.12.6.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    # ------------------------------------------------------------------ #
    # CI/CD & SUPPLY CHAIN                                               #
    # ------------------------------------------------------------------ #
    "gha_injection": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    "gha_unpinned_action": ["SOC2:CC7.1", "ISO:A.12.5.1"],
    "gha_secret_in_log": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    # ------------------------------------------------------------------ #
    # REPOSITORY & GOVERNANCE (no GDPR/DPDP — process findings)          #
    # ------------------------------------------------------------------ #
    "repo_public": ["SOC2:CC6.3", "ISO:A.9.1.1"],
    "branch_unprotected": ["SOC2:CC8.1", "ISO:A.14.2.2"],
    "missing_codeowners": ["SOC2:CC8.1", "ISO:A.14.2.2"],
    "unsigned_commits": ["SOC2:CC8.1", "ISO:A.14.2.2"],
    "missing_security_policy": ["SOC2:CC7.3", "ISO:A.16.1.1"],
    # ------------------------------------------------------------------ #
    # LOGGING & MONITORING                                               #
    # ------------------------------------------------------------------ #
    "sensitive_data_logged": ["SOC2:CC7.2", "ISO:A.12.4.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "insufficient_logging": ["SOC2:CC7.2", "ISO:A.12.4.1"],
    # ------------------------------------------------------------------ #
    # DATA EXPOSURE                                                      #
    # ------------------------------------------------------------------ #
    "pii_in_source": ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    "debug_mode_enabled": ["SOC2:CC7.1", "ISO:A.12.6.1"],
    "verbose_error_exposure": ["SOC2:CC6.6", "ISO:A.14.2.5"],
    # ------------------------------------------------------------------ #
    # CI/CD                                                               #
    # ------------------------------------------------------------------ #
    "cicd_plaintext_secret":      ["SOC2:CC6.1", "ISO:A.9.4.3", "GDPR:Art. 32", "DPDP:Rule 8"],
    "missing_sast_gate":          ["SOC2:CC8.1", "ISO:A.8.25", "ISO:A.8.28"],
    "unsigned_artifact_publish":  ["SOC2:CC8.1", "ISO:A.8.25"],
    # ------------------------------------------------------------------ #
    # DATA CLASSIFICATION                                                 #
    # ------------------------------------------------------------------ #
    "pii_field_unencrypted":              ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "sensitive_category_data_detected":   ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 9", "DPDP:Rule 4"],
    # ------------------------------------------------------------------ #
    # IaC / CONFIG                                                        #
    # ------------------------------------------------------------------ #
    "iac_storage_misconfigured":  ["SOC2:CC6.1", "ISO:A.8.2.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "iac_network_exposed":        ["SOC2:CC6.6", "ISO:A.13.1.1"],
    "iac_encryption_missing":     ["SOC2:CC6.7", "ISO:A.10.1.1", "GDPR:Art. 32", "DPDP:Rule 8"],
    "iac_logging_missing":        ["SOC2:CC7.2", "ISO:A.12.4.1"],
    # ------------------------------------------------------------------ #
    # SBOM / LICENSE                                                      #
    # ------------------------------------------------------------------ #
    "copyleft_license_risk": ["SOC2:CC9.1", "ISO:A.5.21"],
    "unmaintained_dependency": ["SOC2:CC9.1", "ISO:A.5.21", "ISO:A.5.23"],
}

# Control names (SOC2 + ISO27001) — fully enumerated for deterministic mapping
_CONTROL_NAMES: dict[str, str] = {
    # SOC 2
    "CC6.1": "Logical Access Security",
    "CC6.3": "Access Restriction",
    "CC6.6": "Threat Protection from Unauthorized Sources",
    "CC6.7": "Transmission of Data",
    "CC7.1": "Vulnerability Management",
    "CC7.2": "System Monitoring",
    "CC7.3": "Incident Response",
    "CC8.1": "Change Management",
    "CC9.1": "Vendor & Third-Party Risk",
    # ISO 27001
    "A.9.2.3": "Management of Privileged Access Rights",
    "A.9.4.1": "Information Access Restriction",
    "A.9.4.2": "Secure Log-on Procedures",
    "A.9.4.3": "Password Management System",
    "A.9.1.1": "Access Control Policy",
    "A.10.1.1": "Policy on the Use of Cryptographic Controls",
    "A.10.1.2": "Key Management",
    "A.12.1.3": "Capacity Management",
    "A.12.4.1": "Event Logging",
    "A.12.5.1": "Installation of Software on Operational Systems",
    "A.12.6.1": "Management of Technical Vulnerabilities",
    "A.14.2.2": "System Change Control Procedures",
    "A.14.2.5": "Secure System Engineering Principles",
    "A.16.1.1": "Incident Management",
    "A.5.21": "ICT Supply Chain Management",
    "A.5.23": "Use of Cloud Services",
    "A.8.2.1": "Information Classification",
    "A.8.25": "Secure Development Lifecycle",
    "A.8.28": "Secure Coding",
    "A.13.1.1": "Network Security Controls",
    "A.13.1.2": "Security of Network Services",
    # GDPR + DPDP
    "gdpr_article_32": "Security of Processing",
    "dpdp_rule_8": "Security Safeguards",
}

# Build CONTROL_MAP from the raw table + control names
for type_key, raw_entries in RAW_CONTROL_MAP.items():
    CONTROL_MAP[type_key] = []
    for raw in raw_entries:
        fw_prefix, ctrl_id = raw.split(":", 1)
        framework = _FW[fw_prefix]
        # Normalize GDPR/DPDP IDs to canonical format
        if framework == "gdpr":
            # "Art. 32" → "gdpr_article_32"
            m = re.match(r"Art\.?\s*(\d+)", ctrl_id)
            if m:
                ctrl_id = f"gdpr_article_{m.group(1)}"
        elif framework == "dpdp":
            # "Rule 8" → "dpdp_rule_8"
            m = re.match(r"Rule\s*(\d+)", ctrl_id)
            if m:
                ctrl_id = f"dpdp_rule_{m.group(1)}"
        name = _CONTROL_NAMES.get(ctrl_id, "")
        CONTROL_MAP[type_key].append({
            "framework": framework,
            "control_id": ctrl_id,
            "control_name": name,
        })

# ---------------------------------------------------------------------------
# CVE CLASSIFIER — LLM-powered subtype detection for dependency CVEs
# ---------------------------------------------------------------------------

CVE_CLASSIFIER_PROMPT = """
You are a security compliance classifier. Your ONLY job is to output a single
finding type key for a given security finding. You do not write explanations,
suggestions, or any other text — only the key.

## Output exactly one of these keys:

### Dependency CVE subtypes
- dependency_cve_dos         -- Pure availability impact only. No data read/write,
                               no auth bypass, no network traversal. Examples:
                               ReDoS, algorithmic DoS, memory exhaustion, crash.
- dependency_cve_network     -- Affects routing, HTTP handling, URL parsing, path
                               resolution, middleware, proxies, redirects. May allow
                               request smuggling, bypass, or SSRF but does not
                               directly read/write user data. Examples: Next.js
                               middleware bypass, fast-uri path traversal in URLs,
                               hono routing issues, express path confusion.
- dependency_cve_data        -- Directly affects confidentiality or integrity of
                               user/application data. Includes: auth libraries,
                               ORM/database libs, serialization/deserialization,
                               session management, JWT libs, encryption libs,
                               file read vulnerabilities (arbitrary file read),
                               XSS in rendering libs (can exfiltrate data).
                               Examples: passport CVE, sequelize injection,
                               jsonwebtoken forgery, any file read, postcss XSS.
- dependency_cve_email       -- CVE in an email/notification/messaging library.
                               These always handle personal data (email addresses,
                               message content). Examples: nodemailer, sendgrid,
                               mailgun, aws-ses wrappers.

## Decision rules (apply in order, stop at first match)

1. If the finding mentions an EMAIL library (nodemailer, sendgrid, mailgun, ses,
   postmark, resend, mailchimp) -> dependency_cve_email

2. If the finding mentions DoS, denial of service, crash, memory exhaustion,
   algorithmic complexity, ReDoS, or resource exhaustion AND mentions no other
   impact -> dependency_cve_dos

3. If the finding mentions: auth, session, JWT, token forgery, password, ORM,
   database, serialization, deserialization, arbitrary file read, XSS in a
   rendering/output library, encryption, or credential -> dependency_cve_data

4. If the finding mentions: routing, middleware, proxy, URL parsing, path resolution,
   HTTP handling, request smuggling, redirect, SSRF -> dependency_cve_network

## Hard rules
- Output ONLY the key. No punctuation, no explanation, no preamble.
- If no key matches confidently, output: dependency_cve_dos
- Never output a key not in the list above.
"""


async def _classify_cve(description: str, client) -> str:
    """Run LLM classifier on a single CVE description (fallback)."""
    if not description or not description.strip():
        return "dependency_cve_dos"
    result = await _batch_classify_cves([(description, "single")], client)
    return result.get("single", "dependency_cve_dos")


BATCH_CLASSIFY_PROMPT = """
You are a security compliance classifier. Classify each CVE below into exactly
one type. Return a valid JSON array where each item has "id" (the given ID)
and "type" (one of the valid types below).

Valid types:
- dependency_cve_dos         -- Pure availability impact. ReDoS, memory exhaustion, crash.
- dependency_cve_network     -- Routing, HTTP handling, URL parsing, middleware, proxies.
- dependency_cve_data        -- Directly affects data confidentiality/integrity. Auth
                               libs, ORM, serialization, file read, session mgmt.
- dependency_cve_email       -- Email/notification library. nodemailer, sendgrid, etc.

Output ONLY valid JSON, no markdown, no explanation.

CVEs to classify:
{cve_list}
"""


async def _batch_classify_cves(
    items: list[tuple[str, str]], client
) -> dict[str, str]:
    """Classify multiple CVE descriptions in a single API call.

    Args: list of (description, id_string) tuples.
    Returns: dict mapping id_string -> finding_type (fallback "dependency_cve_dos").
    """
    if not items:
        return {}

    from app.utils.llm import groq_retry, strip_markdown_fences  # noqa: PLC0415

    valid_types = {
        "dependency_cve_dos", "dependency_cve_network",
        "dependency_cve_data", "dependency_cve_email",
    }

    # Build numbered list for the prompt
    lines = []
    id_map: dict[str, str] = {}
    for i, (desc, id_str) in enumerate(items):
        label = id_str or f"cve_{i}"
        id_map[str(i)] = label
        snippet = (desc or "").strip()[:300]  # truncate to avoid token bloat
        lines.append(f'{i}. [ID: {label}] {snippet}')

    prompt = BATCH_CLASSIFY_PROMPT.format(cve_list="\n".join(lines))

    try:
        resp = await groq_retry(
            lambda: client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                ],
                max_tokens=256,
                temperature=0.0,
            ),
            max_retries=2,
        )
        content = (resp.choices[0].message.content or "").strip()
        content = strip_markdown_fences(content)
        data = json.loads(content)
    except Exception:
        logger.warning("Batch CVE classify failed, falling back to default")
        return {id_str: "dependency_cve_dos" for _, id_str in items}

    # Parse the JSON array response
    results: dict[str, str] = {}
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            eid = str(entry.get("id", ""))
            etype = str(entry.get("type", "")).lower().strip()
            if etype in valid_types:
                results[eid] = etype
    elif isinstance(data, dict):
        # Some models return a dict mapping id -> type instead
        for eid, etype in data.items():
            etype = str(etype).lower().strip()
            if etype in valid_types:
                results[eid] = etype

    # Fill in any missing classifications with defaults
    for _, id_str in items:
        if id_str not in results:
            results[id_str] = "dependency_cve_dos"

    return results


# ---------------------------------------------------------------------------
# FINDING TYPE CLASSIFICATION
# Maps a rule_id (and optionally description) to a type key in CONTROL_MAP.
# ---------------------------------------------------------------------------

# Each rule: (type_key, matchers)
# where matchers is a dict with optional keys:
#   rule_id_exact: exact match on rule_id
#   rule_id_prefix: rule_id starts with this string
#   rule_id_contains: substring in rule_id
#   rule_id_re: regex match on rule_id
#   desc_contains: substring in description (checked if rule_id matches failed)
_CLASSIFICATION_RULES: list[tuple[str, dict]] = [
    # -- GitHub findings (exact rule_id) --
    ("repo_public", {"rule_id_exact": "github_public_repo"}),
    ("branch_unprotected", {"rule_id_exact": "github_branch_protection"}),
    ("missing_authn", {"rule_id_exact": "github_mfa"}),

    # -- Semgrep: Docker --
    ("docker_root", {"rule_id_prefix": "dockerfile.security"}),
    ("docker_secret_exposed", {"rule_id_contains": "dockerfile.secret"}),
    ("docker_secret_exposed", {"rule_id_contains": "docker-compose.secret"}),
    ("docker_no_resource_limits", {"rule_id_contains": "resource-limit"}),
    ("docker_privileged_mode", {"rule_id_contains": "privileged"}),
    ("docker_unverified_image", {"rule_id_contains": "unverified-image"}),

    # -- Semgrep: Secrets --
    ("hardcoded_secret", {"rule_id_contains": "hardcoded-password"}),
    ("hardcoded_secret", {"rule_id_contains": "hardcoded-credential"}),
    ("hardcoded_secret", {"rule_id_contains": "hardcoded-tmp"}),
    ("hardcoded_secret", {"rule_id_contains": "hardcoded"}),
    ("hardcoded_secret", {"rule_id_contains": ".secret."}),
    ("jwt_exposed", {"rule_id_contains": "jwt"}),
    ("cloud_credentials_exposed", {"rule_id_contains": "aws-access"}),
    ("cloud_credentials_exposed", {"rule_id_contains": "github-pat"}),
    ("cloud_credentials_exposed", {"rule_id_contains": "generic.secrets"}),

    # -- Semgrep: Crypto --
    ("tls_disabled", {"rule_id_contains": "no-auth-over-http"}),
    ("tls_disabled", {"rule_id_contains": "tls"}),
    ("tls_disabled", {"rule_id_contains": "ssl"}),
    ("weak_hash", {"rule_id_contains": "md5"}),
    ("weak_hash", {"rule_id_contains": "sha1"}),
    ("weak_hash", {"rule_id_contains": "use-md5"}),
    ("weak_hash", {"rule_id_contains": "use-sha1"}),
    ("weak_rng", {"rule_id_contains": ".Random"}),
    ("weak_rng", {"rule_id_contains": "random"}),
    ("weak_cipher", {"rule_id_contains": "crypto"}),
    ("weak_cipher", {"rule_id_contains": "des"}),
    ("weak_cipher", {"rule_id_contains": "rc4"}),
    ("missing_sri", {"rule_id_contains": "integrity"}),
    ("missing_sri", {"rule_id_contains": "subresource"}),

    # -- Semgrep: Injection --
    ("sql_injection", {"rule_id_contains": "sqli"}),
    ("sql_injection", {"rule_id_contains": "sql-injection"}),
    ("sql_injection_format", {"rule_id_contains": "sql"}),
    ("command_injection", {"rule_id_contains": "subprocess-shell-true"}),
    ("command_injection", {"rule_id_contains": "command-injection"}),
    ("command_injection", {"rule_id_contains": ".exec-use"}),
    ("command_injection", {"rule_id_contains": ".exec\""}),
    ("command_injection", {"rule_id_contains": "audit.exec"}),
    ("ldap_injection", {"rule_id_contains": "ldap"}),
    ("xss", {"rule_id_contains": "xss"}),
    ("template_injection", {"rule_id_contains": "template-injection"}),
    ("log_injection", {"rule_id_contains": "log-injection"}),

    # -- Semgrep: Access Control --
    ("csrf_missing", {"rule_id_contains": "csrf"}),
    ("csrf_missing", {"rule_id_contains": "requestmapping"}),  # Java RequestMapping without method
    ("csrf_missing", {"rule_id_contains": "request-method"}),   # implicit GET mapping
    ("open_redirect", {"rule_id_contains": "open-redirect"}),
    ("open_redirect", {"rule_id_contains": "redirect"}),
    ("trust_boundary_violation", {"rule_id_contains": "trust-boundary"}),
    ("trust_boundary_violation", {"rule_id_contains": "httpservletrequest"}),  # unvalidated input → session
    ("missing_authn", {"rule_id_contains": "missing-auth"}),
    ("broken_authz", {"rule_id_contains": "broken-auth"}),

    # -- Semgrep: Cookies --
    ("cookie_missing_httponly", {"rule_id_contains": "httponly"}),
    ("cookie_missing_secure", {"rule_id_contains": "secure-flag"}),
    ("cookie_missing_samesite", {"rule_id_contains": "samesite"}),

    # -- Semgrep: Path / File --
    ("path_traversal", {"rule_id_contains": "path-traversal"}),
    ("file_inclusion", {"rule_id_contains": "file-inclusion"}),
    ("unrestricted_file_upload", {"rule_id_contains": "unrestricted-file"}),

    # -- Semgrep: SSRF --
    ("ssrf", {"rule_id_contains": "ssrf"}),

    # -- Semgrep: Deserialization --
    ("unsafe_deserialization", {"rule_id_contains": "deserialization"}),
    ("unsafe_deserialization", {"rule_id_contains": "objectinputstream"}),
    ("prototype_pollution", {"rule_id_contains": "prototype-pollution"}),

    # -- Semgrep: DoS --
    ("redos", {"rule_id_contains": "redos"}),
    ("resource_exhaustion_dos", {"rule_id_contains": "denial-of-service"}),

    # -- Semgrep: Git / GHA (order matters: specific before generic) --
    ("gha_secret_in_log", {"rule_id_contains": "secret-in-log"}),
    ("gha_unpinned_action", {"rule_id_contains": "unpinned"}),
    ("gha_injection", {"rule_id_contains": "github-actions"}),
    ("gha_injection", {"rule_id_contains": "script-injection"}),
    ("gha_injection", {"rule_id_contains": "context-injection"}),

    # -- CI/CD security scanner (workflow YAML analysis) --
    ("cicd_plaintext_secret",     {"rule_id_prefix": "cicd_secret_"}),
    ("missing_sast_gate",         {"rule_id_prefix": "cicd_missing_sast_"}),
    ("unsigned_artifact_publish", {"rule_id_prefix": "cicd_unsigned_"}),

    # -- Data classification scanner (rule_ids like "dc_unencrypted_*", "dc_sensitive_*") --
    ("pii_field_unencrypted",            {"rule_id_prefix": "dc_unencrypted_"}),
    ("sensitive_category_data_detected", {"rule_id_prefix": "dc_sensitive_"}),

    # -- Semgrep: Plaintext HTTP --
    ("plaintext_http", {"rule_id_contains": "no-auth-over-http"}),
    ("plaintext_http", {"rule_id_contains": "plaintext"}),

    # -- Semgrep: Sensitive data / logging --
    ("sensitive_data_logged", {"rule_id_contains": "sensitive-data"}),
    ("sensitive_data_logged", {"rule_id_contains": "log-injection"}),
    ("log_injection", {"rule_id_contains": "unsafe-formatstring"}),
    ("pii_in_source", {"rule_id_prefix": "pii_"}),  # secrets_pii scanner
    ("pii_in_source", {"rule_id_contains": "pii-in"}),

    # -- SBOM / license scanner --
    ("copyleft_license_risk", {"rule_id_prefix": "sbom_copyleft"}),
    ("unmaintained_dependency", {"rule_id_prefix": "sbom_unmaintained"}),

    # -- IaC / Checkov scanner (rule_ids like "checkov_CKV_AWS_53") --
    ("iac_storage_misconfigured",  {"rule_id_prefix": "checkov_storage_"}),
    ("iac_network_exposed",        {"rule_id_prefix": "checkov_network_"}),
    ("iac_encryption_missing",     {"rule_id_prefix": "checkov_encryption_"}),
    ("iac_logging_missing",        {"rule_id_prefix": "checkov_logging_"}),
    ("iac_storage_misconfigured",  {"rule_id_contains": "checkov_CKV_AWS_53"}),
    ("iac_storage_misconfigured",  {"rule_id_contains": "checkov_CKV_AWS_54"}),
    ("iac_storage_misconfigured",  {"rule_id_contains": "checkov_CKV_AWS_55"}),
    ("iac_network_exposed",        {"rule_id_contains": "checkov_CKV_AWS_20"}),
    ("iac_network_exposed",        {"rule_id_contains": "checkov_CKV_AWS_21"}),
    ("iac_network_exposed",        {"rule_id_contains": "checkov_CKV_AWS_24"}),
    ("iac_network_exposed",        {"rule_id_contains": "checkov_CKV_AWS_25"}),
    ("iac_encryption_missing",     {"rule_id_contains": "checkov_encrypt"}),
    ("iac_logging_missing",        {"rule_id_contains": "checkov_log_"}),
    ("iac_logging_missing",        {"rule_id_contains": "checkov_CKV_AWS_14"}),
    ("iac_logging_missing",        {"rule_id_contains": "checkov_CKV_AWS_15"}),

    # -- IaC catch-all (any checkov finding not in specific rules above) --
    ("iac_storage_misconfigured",  {"rule_id_prefix": "checkov_"}),
    ("insufficient_logging", {"rule_id_contains": "no-log"}),  # noqa: SIM114 — separate type

    # -- Semgrep: Debug / Error --
    ("debug_mode_enabled", {"rule_id_contains": "debug-mode"}),
    ("debug_mode_enabled", {"rule_id_contains": "debug.enabled"}),
    ("verbose_error_exposure", {"rule_id_contains": "stack-trace"}),
    ("verbose_error_exposure", {"rule_id_contains": "verbose-error"}),

    # -- OSV (prefixed rule_ids like "osv_xstream", "osv_nodemailer") --
    # Classified by package name — heuristic based on package keywords
    ("dependency_cve_data", {"rule_id_prefix": "osv_", "desc_contains": ("sql", "db", "database", "crypto", "encrypt", "auth", "token", "session", "password", "secret", "xstream", "serial")}),
    ("dependency_cve_email", {"rule_id_prefix": "osv_", "desc_contains": ("mail", "email", "smtp", "nodemailer", "sendmail")}),
    ("dependency_cve_network", {"rule_id_prefix": "osv_", "desc_contains": ("http", "request", "fetch", "url", "uri", "route", "hono", "express", "qs", "querystring")}),
    ("dependency_cve_dos", {"rule_id_prefix": "osv_", "desc_contains": ("dos", "regex", "redos", "repeated", "coercion")}),
    ("dependency_cve_network", {"rule_id_prefix": "osv_"}),  # fallback for unclassified OSV

    # -- Gitleaks secrets scanner (rule_ids like "gitleaks_aws-token", "gitleaks_jwt") --
    ("hardcoded_secret",           {"rule_id_prefix": "gitleaks_"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_aws"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_google"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_azure"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_gitlab"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_github"}),
    ("cloud_credentials_exposed",  {"rule_id_contains": "gitleaks_slack"}),
    ("jwt_exposed",                {"rule_id_contains": "gitleaks_jwt"}),
    ("private_key_exposed",        {"rule_id_contains": "gitleaks_private-key"}),
    ("private_key_exposed",        {"rule_id_contains": "gitleaks_ssh"}),
    ("private_key_exposed",        {"rule_id_contains": "gitleaks_pem"}),
    ("private_key_exposed",        {"rule_id_contains": "gitleaks_rsa"}),
    # -- Generic keyword fallbacks (checked against rule_id, then description) --
    ("hardcoded_secret", {"rule_id_contains": "password", "source_weight": 0.5}),
    ("hardcoded_secret", {"rule_id_contains": "credential", "source_weight": 0.5}),
    ("hardcoded_secret", {"rule_id_contains": "apikey", "source_weight": 0.5}),
    ("hardcoded_secret", {"rule_id_contains": "token", "source_weight": 0.5}),
    ("weak_hash", {"rule_id_contains": "hash", "source_weight": 0.5}),
    ("xss", {"rule_id_contains": "cross-site", "source_weight": 0.5}),
    ("open_redirect", {"rule_id_contains": "redirect", "source_weight": 0.5}),
]

# Fallback for findings that don't match any classification
_DEFAULT_TYPE = "dependency_cve_network"  # safe default

# ---------------------------------------------------------------------------
# REMEDIATION MAP — per finding-type remediation text
# ---------------------------------------------------------------------------

REMEDIATION_MAP: dict[str, str] = {
    # Container / infra
    "docker_root": "Add a non-root USER directive at the end of the Dockerfile (e.g. USER appuser). Never run containers as root.",
    "docker_secret_exposed": "Remove hardcoded secrets from Dockerfiles. Use Docker build secrets or a secrets manager (e.g. HashiCorp Vault).",
    "docker_unverified_image": "Pin container images to a specific digest (sha256:) and pull from trusted registries only.",
    "docker_no_resource_limits": "Set CPU/memory limits in container runtime configuration or orchestrator deployment specs.",
    "docker_privileged_mode": "Remove the --privileged flag. Grant only the capabilities the container actually needs (--cap-drop=ALL --cap-add=...).",
    "iac_docker_healthcheck": "Add a HEALTHCHECK instruction to your Dockerfile. Example: HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
    "iac_docker_user": "Add a non-root USER directive at the end of your Dockerfile. Example: RUN useradd -r appuser && USER appuser",
    # Secrets / credentials
    "hardcoded_secret": "Move secrets to environment variables (e.g. .env) or a secrets manager (Vault, AWS Secrets Manager). Never commit secrets.",
    "jwt_exposed": "Rotate the exposed JWT immediately. Store signing keys in a secrets manager and never log or commit them.",
    "private_key_exposed": "Revoke the exposed key immediately and generate a new one. Store private keys in a secrets manager with restricted access.",
    "cloud_credentials_exposed": "Rotate the cloud credentials immediately. Use IAM roles or workload identity federation instead of long-lived keys.",
    # Crypto
    "tls_disabled": "Re-enable TLS verification. Set NODE_TLS_REJECT_UNAUTHORIZED=1 and never set rejectUnauthorized=false in production.",
    "weak_hash": "Replace MD5/SHA-1 with SHA-256 or SHA-3 for hashing. Use bcrypt/argon2 for password storage.",
    "weak_rng": "Replace Math.random() with crypto.randomBytes() (Node.js) or SecureRandom (Java). Never use non-cryptographic RNG for security.",
    "hardcoded_crypto_key": "Move encryption keys to a key management system (KMS, Vault). Never hardcode keys in source code.",
    "weak_cipher": "Replace DES/RC4 with AES-256-GCM or ChaCha20-Poly1305. Avoid ECB mode — use GCM or CBC with HMAC.",
    # Injection
    "sql_injection": "Replace string concatenation in SQL queries with parameterized queries or an ORM that uses prepared statements.",
    "command_injection": "Use a safe API (e.g. execFile instead of exec) and validate/sanitize all user input before passing to shell commands.",
    "ldap_injection": "Use parameterized LDAP queries (e.g. ldapjs with filters) and sanitize user input before constructing DN strings.",
    "xss": "Use context-aware auto-escaping templates (React JSX, Handlebars) and set Content-Security-Policy headers. Never use dangerouslySetInnerHTML.",
    "template_injection": "Use sandboxed template engines (e.g. Liquid, Handlebars partials) and never pass user input directly to eval-like functions.",
    "log_injection": "Replace string interpolation in logging (util.format, console.log) with structured logging (pino, winston). Never let user input control format strings.",
    # Access control / session
    "csrf_missing": "Add CSRF tokens to all state-changing requests. Use SameSite=Strict cookies and CSRF middleware (e.g. csurf).",
    "open_redirect": "Validate redirect URLs against an allowlist. Never redirect to user-supplied URL parameters without validation.",
    "missing_authn": "Add authentication checks to all privileged endpoints. Use an auth middleware that runs before route handlers.",
    "broken_authz": "Implement access control checks on every endpoint. Use a policy engine (e.g. CASL, Pundit) rather than inline checks.",
    # Cookies / transport
    "cookie_missing_httponly": "Add the HttpOnly flag to cookies that don't need client-side JS access. Set it via cookie options: { httpOnly: true }.",
    "cookie_missing_secure": "Add the Secure flag to all cookies so they're only sent over HTTPS. Set { secure: true } in cookie options.",
    "cookie_missing_samesite": "Set SameSite=Lax or SameSite=Strict on all cookies to prevent CSRF via cross-site requests.",
    "plaintext_http": "Redirect all HTTP traffic to HTTPS using HSTS headers (Strict-Transport-Security). Configure a reverse proxy to terminate TLS.",
    # Path / file
    "path_traversal": "Validate and normalize file paths using path.resolve() and ensure they stay within an allowed base directory.",
    "file_inclusion": "Restrict file includes to a whitelist of allowed paths. Never use user input to construct include paths.",
    "unrestricted_file_upload": "Validate file type by MIME and magic bytes, limit file size, and store uploads outside the web root.",
    # SSRF
    "ssrf": "Restrict outbound HTTP to a whitelist of allowed hosts. Use a forward proxy and validate redirect targets.",
    # Deserialization
    "unsafe_deserialization": "Replace native serialization (JSON.parse with reviver, eval) with safe alternatives like schema-validated JSON.",
    "prototype_pollution": "Use Object.create(null) for maps, freeze trusted objects, and validate object keys against an allowlist.",
    # CVE / dependency
    "dependency_cve_dos": "Update the affected package to the latest patched version. Run npm audit or pip-audit regularly.",
    "dependency_cve_network": "Update the affected package to a version with a fix. If no fix exists, add a WAF rule or middleware to mitigate.",
    "dependency_cve_data": "Update the affected package immediately. If a CVE allows data exfiltration, rotate any potentially exposed secrets.",
    "dependency_cve_email": "Update the affected library. If immediate update isn't possible, restrict outbound SMTP to known relay hosts.",
    # CI/CD / supply chain
    "cicd_plaintext_secret": "Replace the hardcoded value with ${{ secrets.NAME }}. Add secret is the repository settings.",
    "missing_sast_gate": "Add a SAST scanning step (CodeQL, Semgrep, Snyk) to CI/CD pull request workflows and block on high-severity findings.",
    "unsigned_artifact_publish": "Add a signing step (cosign, GPG) before publish commands. Verify signatures in the deployment pipeline.",
    # Repo / governance
    "repo_public": "Review whether the repository should be private. If it must be public, ensure no secrets are committed.",
    "branch_unprotected": "Enable branch protection rules: require PR reviews, status checks, and signed commits on the default branch.",
    "missing_codeowners": "Add a CODEOWNERS file in .github/ to auto-assign PR reviewers based on code paths.",
    "unsigned_commits": "Enable signed commit enforcement in branch protection settings. Configure GPG commit signing in git.",
    "missing_security_policy": "Create a SECURITY.md file explaining how to responsibly report vulnerabilities.",
    # Logging / monitoring
    "sensitive_data_logged": "Remove sensitive data (PII, credentials) from logs. Use structured logging with redaction for known sensitive fields.",
    "insufficient_logging": "Add structured logging for authentication events, access control failures, and data changes.",
    # Data exposure
    "pii_in_source": "Remove the hardcoded PII from source code. Use environment variables, config files excluded from version control, or a secrets manager.",
    "pii_field_unencrypted": "Add column-level encryption (e.g. pgcrypto, Mongoose encrypt) for PII fields. Use AES-256-GCM or similar.",
    "sensitive_category_data_detected": "Apply additional access controls and encryption for GDPR Art. 9 / DPDP Rule 4 special-category data fields.",
    # IaC
    "iac_storage_misconfigured": "Restrict public access to storage resources. Use bucket policies with least-privilege access and enable versioning.",
    "iac_network_exposed": "Restrict security group ingress to specific IP ranges. Never use 0.0.0.0/0 for sensitive ports.",
    "iac_encryption_missing": "Enable server-side encryption (AES-256 or AWS KMS) on storage and database resources in IaC templates.",
    "iac_logging_missing": "Enable access logging and audit trails on all infrastructure resources (S3 access logs, CloudTrail, etc.).",
    # SBOM / license
    "copyleft_license_risk": "Review the dependency's license terms with legal. Consider replacing GPL/AGPL dependencies with permissively-licensed alternatives.",
    "unmaintained_dependency": "Replace the package with an actively maintained alternative. If no alternative exists, fork and maintain internally.",
}

# Finding types that should NEVER carry GDPR/DPDP tags.
# These are governance/infrastructure findings, not data protection ones.
# Filtered at the get_controls() level so no code path can add them.
GDPR_DPDP_EXCLUDED_TYPES = {
    "repo_public",
    "branch_unprotected",
    "missing_codeowners",
    "unsigned_commits",
    "missing_security_policy",
    "docker_root",
    "docker_unverified_image",
    "docker_no_resource_limits",
    "docker_privileged_mode",
    "iac_docker_healthcheck",
    "iac_docker_user",
    "copyleft_license_risk",
    "unmaintained_dependency",
    "iac_network_exposed",
    "iac_logging_missing",
    "missing_sast_gate",
    "unsigned_artifact_publish",
}


def _classify_finding_type(
    rule_id: str, description: str = "", preclassified: str | None = None
) -> str:
    """Map a rule_id (and optional description) to a finding-type key in CONTROL_MAP.

    If preclassified is provided (e.g. from the CVE LLM classifier), it takes
    precedence over all other classification logic.

    Returns _DEFAULT_TYPE if nothing matches.
    """
    if preclassified:
        return preclassified

    rid = rule_id.lower().strip() if rule_id else ""
    desc = description.lower().strip() if description else ""

    # Hardcoded exact-rule_id overrides — bypass all classifier rules.
    # These are known rule_ids from our GitHub/semgrep nodes that MUST
    # map to specific types regardless of any other matching logic.
    _HARDCODED: dict[str, str] = {
        "github_public_repo": "repo_public",
        "github_branch_protection": "branch_unprotected",
        "github_mfa": "missing_authn",
    }
    if rid in _HARDCODED:
        return _HARDCODED[rid]

    for type_key, matcher in _CLASSIFICATION_RULES:
        # Check exact match
        exact = matcher.get("rule_id_exact")
        if exact and rid == exact.lower():
            return type_key

        # Check prefix match
        prefix = matcher.get("rule_id_prefix")
        if prefix and rid.startswith(prefix.lower()):
            # If desc_contains is specified, also check description
            desc_kw = matcher.get("desc_contains")
            if desc_kw:
                if any(kw in desc for kw in desc_kw):
                    return type_key
                continue  # desc_contains didn't match — keep trying
            return type_key

        # Check contains match on rule_id
        contains = matcher.get("rule_id_contains")
        if contains and contains.lower() in rid:
            return type_key

        # Check contains match on description (used for OSV sub-classification)
        # Only check desc_contains if rule_id already matched a prefix
        # (handled above via the desc_contains key in the rule)

    return _DEFAULT_TYPE


def get_controls(
    rule_id: str,
    description: str = "",
    preclassified: str | None = None,
) -> list[dict]:
    """Return deterministic control mappings for a finding.

    Uses finding-type classification to look up controls from CONTROL_MAP.
    The LLM never chooses the control — it only writes explanations.

    preclassified: optional type hint from the CVE LLM classifier
                   (takes precedence over heuristic classification).
    """
    finding_type = _classify_finding_type(rule_id, description, preclassified)
    result = CONTROL_MAP.get(finding_type)
    if result:
        controls = list(result)
    else:
        controls = list(CONTROL_MAP.get(_DEFAULT_TYPE, []))

    # Hard exclusion: governance/infra types never carry GDPR/DPDP
    if finding_type in GDPR_DPDP_EXCLUDED_TYPES:
        controls = [c for c in controls if c["framework"] not in ("gdpr", "dpdp")]

    return controls


# ---------------------------------------------------------------------------
# RESOLVE CONTROLS (SOC2/ISO extraction for LLM batch)
# ---------------------------------------------------------------------------

def _resolve_controls(findings: list[Finding]) -> dict[str, dict]:
    """Resolve SOC2 and ISO controls for each finding by rule_id.

    Returns dict mapping rule_id -> dict with soc2 and iso control info.
    Only SOC2 and ISO are extracted (GDPR/DPDP come via curated table).
    """
    resolved: dict[str, dict] = {}
    for finding in findings:
        rule_id = finding.get("rule_id") or ""
        if rule_id in resolved:
            continue
        description = finding.get("description", "")
        preclassified = finding.get("finding_type") if isinstance(finding, dict) else None
        controls = get_controls(rule_id, description, preclassified)
        soc2_control = iso_control = None
        for c in controls:
            if c["framework"] == "soc2":
                soc2_control = c
            elif c["framework"] == "iso27001":
                iso_control = c
        resolved[rule_id] = {
            "description": finding.get("description", ""),
            "soc2_control_id": soc2_control["control_id"] if soc2_control else None,
            "soc2_control_name": soc2_control["control_name"] if soc2_control else None,
            "iso_control_id": iso_control["control_id"] if iso_control else None,
            "iso_control_name": iso_control["control_name"] if iso_control else None,
        }
    return resolved


# ---------------------------------------------------------------------------
# LLM BATCH — explanations only, never controls
# ---------------------------------------------------------------------------

CHUNK_SIZE = 5


async def _batch_chunk(
    client: AsyncGroq, chunk: list[dict]
) -> list[dict] | None:
    """Send one chunk of findings to Groq and return parsed explanations."""
    prompt = (
        "You are a compliance expert. For each finding below, explain in 1 sentence why "
        "it violates the mapped SOC2 and ISO27001 controls.\n"
        "Return a JSON array where each item has: "
        "rule_id, soc2_explanation, iso_explanation.\n"
        "Only return valid JSON — no markdown, no extra text.\n"
        f"Findings: {json.dumps(chunk)}"
    )

    response = await groq_retry(
        lambda: client.chat.completions.create(
            model=LLM_MODEL, messages=[{"role": "user", "content": prompt}]
        )
    )
    content = response.choices[0].message.content or ""
    content = strip_markdown_fences(content)
    return json.loads(content)


async def _map_single_finding(
    client: AsyncGroq, finding: Finding, info: dict
) -> list[dict]:
    """Fallback: per-finding Groq call for one finding's SOC2 + ISO."""
    rule_id = finding.get("rule_id") or ""
    soc2_id = info.get("soc2_control_id")
    iso_id = info.get("iso_control_id")
    soc2_name = info.get("soc2_control_name")
    iso_name = info.get("iso_control_name")
    description = finding.get("description", "")

    results = []
    for control_id, ctrl_name, framework, fw_key in [
        (soc2_id, soc2_name, "soc2", "soc2"),
        (iso_id, iso_name, "iso27001", "iso"),
    ]:
        if not control_id:
            continue
        try:
            resp = await groq_retry(
                lambda cid=control_id, cn=ctrl_name, fw=framework: client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=[
                        {
                            "role": "user",
                            "content": (
                                f"Given this security finding: {description}\n"
                                f"Explain in 1 sentence why it violates {fw.upper()} "
                                f"control {cid} ({cn}). Be specific."
                            ),
                        }
                    ],
                ),
                max_retries=2,
            )
            explanation = resp.choices[0].message.content or ""
        except Exception:
            explanation = "LLM call failed. Unable to generate explanation."

        results.append(
            {
                "rule_id": rule_id,
                f"{fw_key}_explanation": explanation,
            }
        )
    return results


async def batch_map_findings_soc2_iso(findings: list[Finding]) -> list[MappedControl]:
    if not findings:
        return []

    client = AsyncGroq(api_key=GROQ_API_KEY)
    resolved = _resolve_controls(findings)

    # Build batch input — includes control_ids for LLM context but LLM only returns explanations
    batch_input = []
    for finding in findings:
        rule_id = finding.get("rule_id") or ""
        info = resolved.get(rule_id, {})
        batch_input.append(
            {
                "rule_id": rule_id,
                "description": info.get("description", finding.get("description", "")),
                "soc2_control_id": info.get("soc2_control_id"),
                "soc2_control_name": info.get("soc2_control_name"),
                "iso_control_id": info.get("iso_control_id"),
                "iso_control_name": info.get("iso_control_name"),
            }
        )

    # Build a lookup map for findings by rule_id
    findings_by_rule: dict[str, Finding] = {}
    for f in findings:
        rid = f.get("rule_id") or ""
        findings_by_rule[rid] = f

    # Chunk into smaller batches for reliable JSON responses
    all_explanations: list[dict] = []
    for i in range(0, len(batch_input), CHUNK_SIZE):
        chunk = batch_input[i : i + CHUNK_SIZE]
        try:
            explanations = await _batch_chunk(client, chunk)
            all_explanations.extend(explanations)
        except Exception as exc:
            logger.warning(
                "Batch chunk %d/%d failed (%s), per-finding fallback",
                i // CHUNK_SIZE + 1,
                (len(batch_input) + CHUNK_SIZE - 1) // CHUNK_SIZE,
                exc,
            )
            for entry in chunk:
                rule_id = entry["rule_id"]
                finding = findings_by_rule.get(rule_id)
                if not finding:
                    continue
                info = resolved.get(rule_id, {})
                single = await _map_single_finding(client, finding, info)
                all_explanations.extend(single)

    return _explanations_to_mapped_controls(all_explanations, findings)


def _explanations_to_mapped_controls(
    explanations: list[dict], findings: list[Finding]
) -> list[MappedControl]:
    finding_map: dict[str, Finding] = {}
    for f in findings:
        rule_id = f.get("rule_id") or ""
        if rule_id not in finding_map:
            finding_map[rule_id] = f

    mapped: list[MappedControl] = []
    for item in explanations:
        rule_id = item.get("rule_id", "")
        finding = finding_map.get(rule_id)
        if not finding:
            continue

        soc2_exp = item.get("soc2_explanation", "")
        iso_exp = item.get("iso_explanation", "")

        # ALWAYS use deterministic controls from the lookup table.
        # The LLM only provides explanations; it never chooses the control_id.
        description = finding.get("description", "")
        preclassified = finding.get("finding_type") if isinstance(finding, dict) else None
        resolved_controls = get_controls(rule_id, description, preclassified)
        soc2_id = None
        soc2_name = ""
        iso_id = None
        iso_name = ""
        for c in resolved_controls:
            if c["framework"] == "soc2":
                soc2_id = c["control_id"]
                soc2_name = c["control_name"]
            elif c["framework"] == "iso27001":
                iso_id = c["control_id"]
                iso_name = c["control_name"]

        if soc2_id and soc2_exp:
            mapped.append(
                {
                    "finding": finding,
                    "framework": "soc2",
                    "control_id": soc2_id,
                    "control_name": soc2_name,
                    "explanation": soc2_exp,
                }
            )
        if iso_id and iso_exp:
            mapped.append(
                {
                    "finding": finding,
                    "framework": "iso27001",
                    "control_id": iso_id,
                    "control_name": iso_name,
                    "explanation": iso_exp,
                }
            )

    return mapped
