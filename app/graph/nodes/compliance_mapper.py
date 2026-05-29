from app.graph.state import AuditState, Finding, MappedControl
from app.mapper.controls import map_finding_to_controls
from app.mapper.rag_mapper import map_finding_gdpr_dpdp


async def run_compliance_mapper(state: AuditState) -> dict:
    try:
        findings = [
            *state.get("semgrep_findings", []),
            *state.get("osv_findings", []),
            *state.get("github_findings", []),
        ]
        deduplicated_findings = await _deduplicate_by_rule_id(findings)

        mapped_controls: list[MappedControl] = []
        for finding in deduplicated_findings:
            mapped_controls.extend(await map_finding_to_controls(finding))
            mapped_controls.extend(await map_finding_gdpr_dpdp(finding))

        return {"mapped_controls": mapped_controls}
    except Exception as exc:
        return {"mapped_controls": [], "error": str(exc)}


async def _deduplicate_by_rule_id(findings: list[Finding]) -> list[Finding]:
    deduplicated: dict[str, Finding] = {}
    for index, finding in enumerate(findings):
        rule_id = finding.get("rule_id") or f"finding_{index}"
        if rule_id not in deduplicated:
            deduplicated[rule_id] = finding
    return list(deduplicated.values())
