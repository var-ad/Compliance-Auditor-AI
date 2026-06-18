import json
import logging

from groq import AsyncGroq

from app.graph.state import Finding, MappedControl
from app.utils.config import GROQ_API_KEY, LLM_MODEL
from app.utils.llm import groq_retry, strip_markdown_fences

logger = logging.getLogger(__name__)

CONTROL_MAP = {
    "github_mfa": [
        {
            "framework": "soc2",
            "control_id": "CC6.2",
            "control_name": "Logical Access — Authentication",
        },
        {
            "framework": "iso27001",
            "control_id": "A.9.4.2",
            "control_name": "Secure Log-on Procedures",
        },
    ],
    "github_branch_protection": [
        {
            "framework": "soc2",
            "control_id": "CC8.1",
            "control_name": "Change Management",
        },
        {
            "framework": "iso27001",
            "control_id": "A.14.2.2",
            "control_name": "System Change Control Procedures",
        },
    ],
    "github_public_repo": [
        {
            "framework": "soc2",
            "control_id": "CC6.3",
            "control_name": "Access Restriction",
        },
        {
            "framework": "iso27001",
            "control_id": "A.9.1.1",
            "control_name": "Access Control Policy",
        },
    ],
    "python.lang.security.audit.hardcoded-password": [
        {"framework": "soc2", "control_id": "CC6.1", "control_name": "Logical Access Controls"},
        {"framework": "iso27001", "control_id": "A.9.4.3", "control_name": "Password Management System"},
    ],
    "python.lang.security.audit.hardcoded-tmp": [
        {"framework": "soc2", "control_id": "CC6.1", "control_name": "Logical Access Controls"},
        {"framework": "iso27001", "control_id": "A.9.4.3", "control_name": "Password Management System"},
    ],
    "python.lang.security.audit.sqli": [
        {"framework": "soc2", "control_id": "CC6.6", "control_name": "Threats from Unauthorized Sources"},
        {"framework": "iso27001", "control_id": "A.14.2.5", "control_name": "Secure System Engineering Principles"},
    ],
    "python.lang.security.audit.crypto.use-md5": [
        {"framework": "soc2", "control_id": "CC6.7", "control_name": "Transmission of Data"},
        {"framework": "iso27001", "control_id": "A.10.1.1", "control_name": "Policy on the Use of Cryptographic Controls"},
    ],
    "python.lang.security.audit.crypto.use-sha1": [
        {"framework": "soc2", "control_id": "CC6.7", "control_name": "Transmission of Data"},
        {"framework": "iso27001", "control_id": "A.10.1.1", "control_name": "Policy on the Use of Cryptographic Controls"},
    ],
    "python.lang.security.audit.exec": [
        {"framework": "soc2", "control_id": "CC6.6", "control_name": "Threats from Unauthorized Sources"},
        {"framework": "iso27001", "control_id": "A.14.2.5", "control_name": "Secure System Engineering Principles"},
    ],
    "python.lang.security.audit.subprocess-shell-true": [
        {"framework": "soc2", "control_id": "CC6.6", "control_name": "Threats from Unauthorized Sources"},
        {"framework": "iso27001", "control_id": "A.14.2.5", "control_name": "Secure System Engineering Principles"},
    ],
    "python.requests.security.no-auth-over-http": [
        {"framework": "soc2", "control_id": "CC6.7", "control_name": "Transmission of Data"},
        {"framework": "iso27001", "control_id": "A.10.1.2", "control_name": "Key Management"},
    ],
    "javascript.lang.security.audit.prototype-pollution": [
        {"framework": "soc2", "control_id": "CC6.6", "control_name": "Threats from Unauthorized Sources"},
        {"framework": "iso27001", "control_id": "A.14.2.5", "control_name": "Secure System Engineering Principles"},
    ],
    "javascript.lang.security.audit.hardcoded-credentials": [
        {"framework": "soc2", "control_id": "CC6.1", "control_name": "Logical Access Controls"},
        {"framework": "iso27001", "control_id": "A.9.4.3", "control_name": "Password Management System"},
    ],
    "generic.secrets.security.detected-aws-access-key": [
        {"framework": "soc2", "control_id": "CC6.1", "control_name": "Logical Access Controls"},
        {"framework": "iso27001", "control_id": "A.9.4.3", "control_name": "Password Management System"},
    ],
    "generic.secrets.security.detected-github-pat": [
        {"framework": "soc2", "control_id": "CC6.1", "control_name": "Logical Access Controls"},
        {"framework": "iso27001", "control_id": "A.9.4.3", "control_name": "Password Management System"},
    ],
}

SECRET_CONTROLS = [
    {
        "framework": "soc2",
        "control_id": "CC6.1",
        "control_name": "Logical Access Controls",
    },
    {
        "framework": "iso27001",
        "control_id": "A.9.4.2",
        "control_name": "Secure Log-on Procedures",
    },
]

INJECTION_CONTROLS = [
    {
        "framework": "soc2",
        "control_id": "CC6.6",
        "control_name": "Threats from Unauthorized Sources",
    },
    {
        "framework": "iso27001",
        "control_id": "A.14.2.5",
        "control_name": "Secure System Engineering Principles",
    },
]

CRYPTO_CONTROLS = [
    {
        "framework": "soc2",
        "control_id": "CC6.7",
        "control_name": "Transmission of Data",
    },
    {
        "framework": "iso27001",
        "control_id": "A.10.1.1",
        "control_name": "Policy on the Use of Cryptographic Controls",
    },
]

FALLBACK_CONTROLS = [
    {
        "framework": "soc2",
        "control_id": "CC7.1",
        "control_name": "Vulnerability Management",
    },
    {
        "framework": "iso27001",
        "control_id": "A.12.6.1",
        "control_name": "Management of Technical Vulnerabilities",
    },
]


def get_controls(rule_id: str) -> list[dict]:
    # Try exact match first
    if rule_id in CONTROL_MAP:
        return CONTROL_MAP[rule_id]

    # Then prefix match — semgrep rule IDs may have suffixes
    for prefix, controls in CONTROL_MAP.items():
        if rule_id.startswith(prefix):
            return controls

    normalized_rule_id = rule_id.lower()
    if "secret" in normalized_rule_id or "hardcoded" in normalized_rule_id:
        return SECRET_CONTROLS
    if "injection" in normalized_rule_id or "sqli" in normalized_rule_id:
        return INJECTION_CONTROLS
    if (
        "crypto" in normalized_rule_id
        or "tls" in normalized_rule_id
        or "ssl" in normalized_rule_id
    ):
        return CRYPTO_CONTROLS
    return FALLBACK_CONTROLS


def _resolve_controls(findings: list[Finding]) -> dict[str, dict]:
    """Resolve SOC2 and ISO controls for each finding by rule_id.

    Returns dict mapping rule_id -> dict with soc2 and iso control info.
    """
    resolved: dict[str, dict] = {}
    for finding in findings:
        rule_id = finding.get("rule_id") or ""
        if rule_id in resolved:
            continue
        controls = get_controls(rule_id)
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


CHUNK_SIZE = 5


async def _batch_chunk(
    client: AsyncGroq, chunk: list[dict]
) -> list[dict] | None:
    """Send one chunk of findings to Groq and return parsed explanations."""
    prompt = (
        "You are a compliance expert. For each finding below, explain in 1 sentence why "
        "it violates the mapped SOC2 and ISO27001 controls.\n"
        "Return a JSON array where each item has: "
        "rule_id, soc2_control_id, soc2_explanation, iso_control_id, iso_explanation.\n"
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
                f"{fw_key}_control_id": control_id,
                f"{fw_key}_explanation": explanation,
            }
        )
    return results


async def batch_map_findings_soc2_iso(findings: list[Finding]) -> list[MappedControl]:
    if not findings:
        return []

    client = AsyncGroq(api_key=GROQ_API_KEY)
    resolved = _resolve_controls(findings)

    # Build batch input
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

        soc2_id = item.get("soc2_control_id")
        soc2_exp = item.get("soc2_explanation", "")
        iso_id = item.get("iso_control_id")
        iso_exp = item.get("iso_explanation", "")

        resolved_controls = get_controls(rule_id)
        soc2_name = ""
        iso_name = ""
        for c in resolved_controls:
            if c["framework"] == "soc2":
                soc2_name = c["control_name"]
            elif c["framework"] == "iso27001":
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
