import json
import logging

from groq import AsyncGroq

from app.graph.state import AuditState, MappedControl
from app.utils.config import GROQ_API_KEY, LLM_MODEL
from app.utils.llm import groq_retry

logger = logging.getLogger(__name__)

FRAMEWORKS = ("soc2", "iso27001", "gdpr", "dpdp")
SEVERITIES = ("critical", "high", "medium", "low")

FRAMEWORK_WEIGHTS = {
    "soc2": 0.35,
    "iso27001": 0.25,
    "gdpr": 0.25,
    "dpdp": 0.15,
}

SEVERITY_WEIGHTS = {
    "critical": -25,
    "high": -15,
    "medium": -7,
    "low": -3,
}


async def run_report_generator(state: AuditState) -> dict:
    try:
        mapped_controls = state.get("mapped_controls", [])
        state_error = state.get("error")

        # If there's an upstream error and no mapped controls, include it in report
        if state_error and not mapped_controls:
            report_dict = {
                "repo_url": state["repo_url"],
                "overall_score": 0,
                "executive_summary": "Audit could not be completed due to errors.",
                "frameworks": _empty_frameworks(),
                "framework_scores": {fw: 0 for fw in FRAMEWORKS},
                "severity_breakdown": {s: 0 for s in SEVERITIES},
                "error": state_error,
            }
            return {"report": json.dumps(report_dict)}

        grouped_controls = _group_by_framework(mapped_controls)
        severity_breakdown = _severity_breakdown(mapped_controls)
        total_findings = sum(severity_breakdown.values())
        framework_scores = _per_framework_scores(mapped_controls)
        overall_score = _weighted_score(framework_scores)

        client = AsyncGroq(api_key=GROQ_API_KEY)
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
        response = await groq_retry(
            lambda: client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
            )
        )
        executive_summary = response.choices[0].message.content or ""

        report_dict = {
            "repo_url": state["repo_url"],
            "overall_score": overall_score,
            "executive_summary": executive_summary,
            "frameworks": grouped_controls,
            "framework_scores": framework_scores,
            "severity_breakdown": severity_breakdown,
        }
        if state_error:
            report_dict["error"] = state_error

        logger.info(
            "Report generated: score=%d, %d controls mapped, framework_scores=%s",
            overall_score,
            len(mapped_controls),
            framework_scores,
        )
        return {"report": json.dumps(report_dict)}
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        return {"report": "", "error": str(exc)}


def _empty_frameworks() -> dict:
    return {
        framework: {"controls_triggered": 0, "findings": []}
        for framework in FRAMEWORKS
    }


def _group_by_framework(mapped_controls: list[MappedControl]) -> dict:
    grouped = _empty_frameworks()
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


def _per_framework_scores(mapped_controls: list[MappedControl]) -> dict[str, int]:
    """Compute a compliance score per framework, independently deduplicated."""
    per_fw_breakdown: dict[str, dict[str, int]] = {
        fw: {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for fw in FRAMEWORKS
    }
    # Per-framework seen set so the same finding counts toward each framework
    fw_seen: dict[str, set[tuple[str, str, str]]] = {
        fw: set() for fw in FRAMEWORKS
    }

    for mc in mapped_controls:
        framework = mc.get("framework", "")
        if framework not in per_fw_breakdown:
            continue
        finding = mc["finding"]
        key = (
            finding.get("tool", ""),
            finding.get("rule_id") or finding.get("title", ""),
            finding.get("description", ""),
        )
        if key in fw_seen[framework]:
            continue
        fw_seen[framework].add(key)
        severity = finding.get("severity", "").lower()
        if severity in per_fw_breakdown[framework]:
            per_fw_breakdown[framework][severity] += 1

    scores = {}
    for framework, breakdown in per_fw_breakdown.items():
        deduction = sum(
            SEVERITY_WEIGHTS[sev] * count for sev, count in breakdown.items()
        )
        scores[framework] = max(0, 100 + deduction)

    return scores


def _weighted_score(framework_scores: dict[str, int]) -> int:
    """Compute overall score as weighted average of per-framework scores."""
    weighted = sum(
        FRAMEWORK_WEIGHTS[fw] * framework_scores.get(fw, 0) for fw in FRAMEWORKS
    )
    return round(weighted)
