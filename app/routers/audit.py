import json
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.graph.graph import compliance_graph, run_audit
from app.graph.state import AuditState
from app.utils.cache import (
    get_cache_key,
    get_cached_report,
    purge_stale_cache,
    save_cached_report,
)
from app.utils.config import GROQ_API_KEY

logger = logging.getLogger(__name__)

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


@router.post("/audit")
async def audit(request: AuditRequest):
    repo_url = request.repo_url

    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY is not configured. Set it in .env to run audits.",
        )

    # Check cache
    cache_key = await get_cache_key(repo_url)
    cached = await get_cached_report(cache_key)
    if cached is not None:
        logger.info("Cache HIT for %s", repo_url)
        return JSONResponse(content=cached, headers={"X-Cache": "HIT"})

    logger.info("Cache MISS for %s (key=%s)", repo_url, cache_key)

    initial_state: AuditState = {
        "repo_url": repo_url,
        "local_path": None,
        "semgrep_findings": [],
        "osv_findings": [],
        "github_findings": [],
        "mapped_controls": [],
        "report": "",
        "error": None,
    }

    try:
        result = await run_audit(initial_state)
        state_error = result.get("error")
        report_str = result.get("report", "")

        if state_error and not report_str:
            logger.error("Audit failed for %s: %s", repo_url, state_error)
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred while running the audit.",
            )

        if not report_str:
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred while running the audit.",
            )

        report_json = json.loads(report_str)

        # Save to cache
        await save_cached_report(cache_key, report_json)

        # Opportunistic stale cache cleanup (non-blocking)
        try:
            await purge_stale_cache()
        except Exception:
            pass

        return JSONResponse(content=report_json, headers={"X-Cache": "MISS"})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Audit failed for %s: %s", repo_url, exc)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing the audit request.",
        ) from exc


@router.get("/audit/status")
async def audit_status():
    try:
        nodes = list(compliance_graph.get_graph().nodes.keys())
        # Filter internal langgraph nodes
        user_nodes = [n for n in nodes if not n.startswith("__")]
    except Exception:
        user_nodes = [
            "orchestrator",
            "semgrep",
            "osv",
            "github",
            "compliance_mapper",
            "report_generator",
        ]
    return {"status": "ready", "graph_nodes": user_nodes}
