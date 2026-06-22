import logging

from langgraph.graph import END, StateGraph

from app.graph.nodes.compliance_mapper import run_compliance_mapper
from app.graph.nodes.github import run_github
from app.graph.nodes.orchestrator import orchestrate
from app.graph.nodes.osv import run_osv
from app.graph.nodes.report_generator import run_report_generator
from app.graph.nodes.scan_cicd_security import run_scan_cicd_security
from app.graph.nodes.scan_data_classification import run_scan_data_classification
from app.graph.nodes.scan_iac_config import run_scan_iac_config
from app.graph.nodes.scan_repo_governance import run_scan_repo_governance
from app.graph.nodes.scan_sbom_license import run_scan_sbom_license
from app.graph.nodes.scan_secrets_pii import run_scan_secrets_pii
from app.graph.nodes.semgrep import run_semgrep
from app.graph.state import AuditState
from app.utils.git import cleanup_repo

logger = logging.getLogger(__name__)


async def _fan_out(state: AuditState) -> dict:
    """Pass-through: dispatches to all 9 parallel scanner branches.

    Returns repo_url so the streaming progress tracker sees this node complete.
    """
    return {"repo_url": state.get("repo_url", "")}


async def _scanner_merge(state: AuditState) -> dict:
    """Merge barrier: increments the run counter.

    The conditional edge waits until all 9 parallel scanner branches
    have triggered this node, then proceeds to compliance_mapper once.
    """
    return {"_mapper_run_count": 1}


def build_graph():
    graph = StateGraph(AuditState)

    graph.add_node("orchestrator", orchestrate)
    graph.add_node("fan_out", _fan_out)
    graph.add_node("semgrep", run_semgrep)
    graph.add_node("osv", run_osv)
    graph.add_node("github", run_github)
    graph.add_node("scan_secrets_pii", run_scan_secrets_pii)
    graph.add_node("scan_repo_governance", run_scan_repo_governance)
    graph.add_node("scan_sbom_license", run_scan_sbom_license)
    graph.add_node("scan_iac_config", run_scan_iac_config)
    graph.add_node("scan_cicd_security", run_scan_cicd_security)
    graph.add_node("scan_data_classification", run_scan_data_classification)
    graph.add_node("scanner_merge", _scanner_merge)
    graph.add_node("compliance_mapper", run_compliance_mapper)
    graph.add_node("report_generator", run_report_generator)

    graph.set_entry_point("orchestrator")

    # orchestrator → route on error, else fan out for parallel scan branches
    def route_after_orchestrator(state: AuditState):
        if state.get("error"):
            return END
        return "fan_out"

    graph.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {"fan_out": "fan_out", END: END},
    )

    # Fan-out: 9 fully parallel scanner branches (no sequential chains)
    graph.add_edge("fan_out", "semgrep")
    graph.add_edge("fan_out", "osv")
    graph.add_edge("fan_out", "github")
    graph.add_edge("fan_out", "scan_secrets_pii")
    graph.add_edge("fan_out", "scan_repo_governance")
    graph.add_edge("fan_out", "scan_sbom_license")
    graph.add_edge("fan_out", "scan_iac_config")
    graph.add_edge("fan_out", "scan_cicd_security")
    graph.add_edge("fan_out", "scan_data_classification")

    # All 9 branches converge at scanner_merge (waits for every branch)
    graph.add_edge("semgrep", "scanner_merge")
    graph.add_edge("osv", "scanner_merge")
    graph.add_edge("github", "scanner_merge")
    graph.add_edge("scan_secrets_pii", "scanner_merge")
    graph.add_edge("scan_repo_governance", "scanner_merge")
    graph.add_edge("scan_sbom_license", "scanner_merge")
    graph.add_edge("scan_iac_config", "scanner_merge")
    graph.add_edge("scan_cicd_security", "scanner_merge")
    graph.add_edge("scan_data_classification", "scanner_merge")

    # Barrier: only proceed to compliance_mapper after all 9 branches
    # have triggered scanner_merge (guarantees complete finding set).
    def _all_scanners_complete(state: AuditState) -> str:
        return "compliance_mapper" if state.get("_mapper_run_count", 0) >= 9 else END
    graph.add_conditional_edges(
        "scanner_merge",
        _all_scanners_complete,
        {"compliance_mapper": "compliance_mapper", END: END},
    )
    graph.add_edge("compliance_mapper", "report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile()


compliance_graph = build_graph()


async def run_audit(initial_state: AuditState) -> AuditState:
    """Run the compliance graph and clean up the cloned repo afterwards."""
    result = None
    try:
        result = await compliance_graph.ainvoke(initial_state)
        return result
    finally:
        local_path = initial_state.get("local_path")
        if local_path is None and result is not None:
            local_path = result.get("local_path")
        if local_path:
            await cleanup_repo(local_path)
