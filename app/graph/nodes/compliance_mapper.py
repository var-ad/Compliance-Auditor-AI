import logging

from app.graph.state import AuditState, Finding, MappedControl

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
from app.mapper.controls import batch_map_findings_soc2_iso
from app.mapper.rag_mapper import batch_map_findings_gdpr_dpdp

logger = logging.getLogger(__name__)


async def run_compliance_mapper(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    try:
        findings = [
            *state.get("semgrep_findings", []),
            *state.get("osv_findings", []),
            *state.get("github_findings", []),
        ]
        deduplicated_findings = await _deduplicate_by_rule_id(findings)

        soc2_iso_mapped = await batch_map_findings_soc2_iso(deduplicated_findings)
        gdpr_dpdp_mapped = await batch_map_findings_gdpr_dpdp(deduplicated_findings)

        mapped_controls: list[MappedControl] = [
            *soc2_iso_mapped,
            *gdpr_dpdp_mapped,
        ]

        logger.info("Mapped %d controls", len(mapped_controls))
        return {"mapped_controls": mapped_controls}
    except Exception as exc:
        logger.error("Compliance mapping failed: %s", exc)
        return {"mapped_controls": [], "error": str(exc)}


async def _deduplicate_by_rule_id(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by rule_id, keeping the most severe entry."""
    deduplicated: dict[str, Finding] = {}
    for index, finding in enumerate(findings):
        rule_id = finding.get("rule_id") or f"finding_{index}"
        existing = deduplicated.get(rule_id)
        if existing is None:
            deduplicated[rule_id] = finding
        else:
            # Keep the finding with the highest severity rank
            curr_rank = SEVERITY_RANK.get(finding.get("severity", "low"), 0)
            exist_rank = SEVERITY_RANK.get(existing.get("severity", "low"), 0)
            if curr_rank > exist_rank:
                deduplicated[rule_id] = finding
    return list(deduplicated.values())
