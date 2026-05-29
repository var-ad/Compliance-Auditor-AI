import os

from dotenv import load_dotenv
from groq import AsyncGroq

from app.graph.state import Finding, MappedControl

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
    if rule_id in CONTROL_MAP:
        return CONTROL_MAP[rule_id]

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


async def map_finding_to_controls(finding: Finding) -> list[MappedControl]:
    mapped_controls: list[MappedControl] = []
    load_dotenv()
    client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))

    for control in get_controls(finding["rule_id"] or ""):
        prompt = (
            f"Given this security finding: {finding['description']}\n"
            f"Explain in 2 sentences why it violates {control['framework'].upper()} "
            f"control {control['control_id']} ({control['control_name']}).\n"
            "Be specific and technical."
        )
        try:
            response = await client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
            )
            explanation = response.choices[0].message.content or ""
        except Exception as exc:
            explanation = str(exc)

        mapped_controls.append(
            {
                "finding": finding,
                "framework": control["framework"],
                "control_id": control["control_id"],
                "control_name": control["control_name"],
                "explanation": explanation,
            }
        )

    return mapped_controls
