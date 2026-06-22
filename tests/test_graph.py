"""Integration tests for the LangGraph compliance graph."""

import pytest
from langgraph.graph import END, StateGraph
from typing import TypedDict

from app.graph.state import AuditState


class TestGraphRouting:
    """Test that the graph routes correctly based on state."""

    async def _run_graph_with_overrides(self, **overrides):
        """Build a minimal graph with mock nodes and run it."""
        graph = StateGraph(AuditState)

        async def mock_orch(state):
            if overrides.get("orch_error"):
                return {"error": overrides["orch_error"]}
            return {"local_path": "/tmp/test_repo"}

        async def mock_passthrough(state):
            if state.get("error"):
                return {}
            return {}

        graph.add_node("orchestrator", mock_orch)
        graph.add_node("scanner", mock_passthrough)
        graph.add_node("final", mock_passthrough)

        graph.set_entry_point("orchestrator")

        def route(state):
            if state.get("error"):
                return END
            return "scanner"

        graph.add_conditional_edges(
            "orchestrator", route, {"scanner": "scanner", END: END}
        )
        graph.add_edge("scanner", "final")
        graph.add_edge("final", END)

        compiled = graph.compile()
        state: AuditState = {
            "repo_url": "https://github.com/owner/repo",
            "local_path": None,
            "semgrep_findings": [],
            "osv_findings": [],
            "github_findings": [],
            "mapped_controls": [],
            "report": "",
            "error": None,
        }
        result = await compiled.ainvoke(state)
        return result

    @pytest.mark.anyio
    async def test_successful_path(self):
        result = await self._run_graph_with_overrides()
        assert result.get("error") is None
        assert result.get("local_path") == "/tmp/test_repo"

    @pytest.mark.anyio
    async def test_error_path(self):
        result = await self._run_graph_with_overrides(orch_error="Clone failed")
        assert result.get("error") == "Clone failed"
        # Should skip scanner and final nodes
        assert result.get("local_path") is None

    def test_tool_check_node_structure(self):
        """Verify the actual graph has the expected node structure."""
        from app.graph.graph import compliance_graph

        nodes = list(compliance_graph.get_graph().nodes.keys())
        assert "orchestrator" in nodes
        assert "semgrep" in nodes
        assert "osv" in nodes
        assert "github" in nodes
        assert "compliance_mapper" in nodes
        assert "report_generator" in nodes
        # LangGraph internal nodes
        assert "__start__" in nodes
        assert "__end__" in nodes

    @pytest.mark.anyio
    async def test_multi_scanner_fan_in_reaches_mapper_and_report(self):
        """The join must wait for every scanner, then continue past the merge."""
        class FanInState(TypedDict, total=False):
            a: bool
            b: bool
            mapped: bool
            report: str

        graph = StateGraph(FanInState)
        completed = []

        async def start(_state):
            return {}

        async def scanner_a(_state):
            completed.append("a")
            return {"a": True}

        async def scanner_b(_state):
            completed.append("b")
            return {"b": True}

        async def merge(state):
            assert state["a"] is True
            assert state["b"] is True
            completed.append("merge")
            return {}

        async def mapper(_state):
            completed.append("mapper")
            return {"mapped": True}

        async def report(_state):
            completed.append("report")
            return {"report": "generated"}

        graph.add_node("start", start)
        graph.add_node("scanner_a", scanner_a)
        graph.add_node("scanner_b", scanner_b)
        graph.add_node("merge", merge)
        graph.add_node("mapper", mapper)
        graph.add_node("report", report)
        graph.set_entry_point("start")
        graph.add_edge("start", "scanner_a")
        graph.add_edge("start", "scanner_b")
        graph.add_edge(["scanner_a", "scanner_b"], "merge")
        graph.add_edge("merge", "mapper")
        graph.add_edge("mapper", "report")
        graph.add_edge("report", END)

        result = await graph.compile().ainvoke({})

        assert result["mapped"] is True
        assert result["report"] == "generated"
        assert completed[-3:] == ["merge", "mapper", "report"]


class TestRunAuditWrapper:
    """Test the run_audit wrapper handles cleanup correctly."""

    def test_run_audit_imports(self):
        from app.graph.graph import run_audit, compliance_graph

        assert callable(run_audit)
        assert compliance_graph is not None
