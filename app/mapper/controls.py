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
    """Run LLM classifier on a CVE description to determine its subtype."""
    if not description or not description.strip():
        return "dependency_cve_dos"
    from app.utils.llm import groq_retry  # noqa: PLC0415
    try:
        resp = await groq_retry(
            lambda: client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": CVE_CLASSIFIER_PROMPT},
                    {"role": "user", "content": description.strip()},
                ],
                max_tokens=16,
                temperature=0.0,
            ),
            max_retries=2,
        )
        result = (resp.choices[0].message.content or "").strip().lower()
        # Validate the result is a known type
        valid_types = {
            "dependency_cve_dos", "dependency_cve_network",
            "dependency_cve_data", "dependency_cve_email",
        }
        if result in valid_types:
            return result
        return "dependency_cve_dos"
    except Exception:
        return "dependency_cve_dos"


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
    ("docker_root", {"rule_id_prefix": "dockerfile.security.run-as-root"}),
    ("docker_secret_exposed", {"rule_id_contains": "dockerfile"}),
    ("docker_secret_exposed", {"rule_id_contains": "docker-compose"}),
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

    # -- Semgrep: Plaintext HTTP --
    ("plaintext_http", {"rule_id_contains": "no-auth-over-http"}),
    ("plaintext_http", {"rule_id_contains": "plaintext"}),

    # -- Semgrep: Sensitive data / logging --
    ("sensitive_data_logged", {"rule_id_contains": "sensitive-data"}),
    ("sensitive_data_logged", {"rule_id_contains": "pii-in"}),
    ("sensitive_data_logged", {"rule_id_contains": "log-injection"}),
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
