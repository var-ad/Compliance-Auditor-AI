import json
import os

from dotenv import load_dotenv
from groq import AsyncGroq

from app.graph.state import AuditState, MappedControl

FRAMEWORKS = ("soc2", "iso27001", "gdpr", "dpdp")
SEVERITIES = ("critical", "high", "medium", "low")


async def run_report_generator(state: AuditState) -> dict:
    try:
        mapped_controls = state.get("mapped_controls", [])
        grouped_controls = _group_by_framework(mapped_controls)
        severity_breakdown = _severity_breakdown(mapped_controls)
        total_findings = sum(severity_breakdown.values())
        overall_score = _overall_score(severity_breakdown)

        load_dotenv()
        client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
        prompt = (
            "You are a compliance auditor writing an executive summary.\n"
            f"Repository: {state['repo_url']}\n"
            f"Overall compliance score: {overall_score}/100\n"
            "Findings summary:\n"
            f"- SOC 2: {grouped_controls['soc2']['controls_triggered']} controls triggered\n"
            f"- ISO 27001: {grouped_controls['iso27001']['controls_triggered']} controls triggered\n"
            f"- GDPR: {grouped_controls['gdpr']['controls_triggered']} controls triggered\n"
            f"- DPDP: {grouped_controls['dpdp']['controls_triggered']} controls triggered\n"
            f"Total findings: {total_findings}\n"
            "Write a 3-sentence executive summary for a technical audience.\n"
            "Be specific, professional, and actionable."
        )
        response = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
        )
        executive_summary = response.choices[0].message.content or ""

        report_dict = {
            "repo_url": state["repo_url"],
            "overall_score": overall_score,
            "executive_summary": executive_summary,
            "frameworks": grouped_controls,
            "severity_breakdown": severity_breakdown,
        }
        return {"report": json.dumps(report_dict)}
    except Exception as exc:
        return {"report": "", "error": str(exc)}


def _group_by_framework(mapped_controls: list[MappedControl]) -> dict:
    grouped = {
        framework: {"controls_triggered": 0, "findings": []}
        for framework in FRAMEWORKS
    }
    control_ids = {framework: set() for framework in FRAMEWORKS}

    for mapped_control in mapped_controls:
        framework = mapped_control.get("framework")
        if framework not in grouped:
            continue
        grouped[framework]["findings"].append(mapped_control)
        control_ids[framework].add(mapped_control["control_id"])

    for framework in FRAMEWORKS:
        grouped[framework]["controls_triggered"] = len(control_ids[framework])

    return grouped


def _severity_breakdown(mapped_controls: list[MappedControl]) -> dict:
    breakdown = {severity: 0 for severity in SEVERITIES}
    seen_findings: set[tuple[str, str, str]] = set()

    for mapped_control in mapped_controls:
        finding = mapped_control["finding"]
        finding_key = (
            finding.get("tool", ""),
            finding.get("rule_id") or finding.get("title", ""),
            finding.get("description", ""),
        )
        if finding_key in seen_findings:
            continue
        seen_findings.add(finding_key)

        severity = finding.get("severity", "").lower()
        if severity in breakdown:
            breakdown[severity] += 1

    return breakdown


def _overall_score(severity_breakdown: dict) -> int:
    score = 100
    score -= 20 * severity_breakdown["critical"]
    score -= 10 * severity_breakdown["high"]
    score -= 5 * severity_breakdown["medium"]
    score -= 2 * severity_breakdown["low"]
    return max(score, 0)
