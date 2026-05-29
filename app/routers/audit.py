import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.graph.graph import compliance_graph
from app.graph.state import AuditState

router = APIRouter(tags=["audit"])


class AuditRequest(BaseModel):
    repo_url: str


class AuditResponse(BaseModel):
    repo_url: str
    overall_score: int
    executive_summary: str
    frameworks: dict
    severity_breakdown: dict
    error: str | None = None


@router.post("/audit", response_model=AuditResponse)
async def audit(request: AuditRequest):
    initial_state: AuditState = {
        "repo_url": request.repo_url,
        "semgrep_findings": [],
        "osv_findings": [],
        "github_findings": [],
        "mapped_controls": [],
        "report": "",
        "error": None,
    }

    try:
        result = await compliance_graph.ainvoke(initial_state)
        if result.get("error"):
            raise HTTPException(status_code=400, detail=result["error"])

        report_json = json.loads(result["report"])
        return AuditResponse(**report_json)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/audit/status")
async def audit_status():
    return {
        "status": "ready",
        "graph_nodes": [
            "orchestrator",
            "semgrep",
            "osv",
            "github",
            "compliance_mapper",
            "report_generator",
        ],
    }
