from langgraph.graph import END, StateGraph

from app.graph.nodes.compliance_mapper import run_compliance_mapper
from app.graph.nodes.github import run_github
from app.graph.nodes.orchestrator import orchestrate
from app.graph.nodes.osv import run_osv
from app.graph.nodes.report_generator import run_report_generator
from app.graph.nodes.semgrep import run_semgrep
from app.graph.state import AuditState


def build_graph():
    graph = StateGraph(AuditState)

    graph.add_node("orchestrator", orchestrate)
    graph.add_node("semgrep", run_semgrep)
    graph.add_node("osv", run_osv)
    graph.add_node("github", run_github)
    graph.add_node("compliance_mapper", run_compliance_mapper)
    graph.add_node("report_generator", run_report_generator)

    graph.set_entry_point("orchestrator")

    def route_after_orchestrator(state: AuditState):
        if state.get("error"):
            return END
        return "scanners"

    graph.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {"scanners": "semgrep", END: END},
    )

    graph.add_edge("semgrep", "osv")
    graph.add_edge("osv", "github")
    graph.add_edge("github", "compliance_mapper")
    graph.add_edge("compliance_mapper", "report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile()


compliance_graph = build_graph()
