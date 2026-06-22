import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.graph.graph import compliance_graph, run_audit
from app.graph.nodes.compliance_mapper import run_compliance_mapper
from app.graph.nodes.report_generator import run_report_generator
from app.graph.progress import (
    ALL_NODES,
    cleanup,
    complete_audit,
    create_audit,
    get_result,
    get_status,
    mark_completed,
    mark_error,
    mark_running,
    save_result,
)
from app.graph.state import AuditState
from app.utils.cache import (
    get_cache_key,
    get_cached_report,
    purge_stale_cache,
    save_cached_report,
)
from app.utils.config import GROQ_API_KEY
from app.utils.git import SOURCE_ZIP, cleanup_repo, extract_zip

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


# ── Synchronous audit (original, blocks until done) ──────────────────────


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
        "input_source": None,
        "repo_name": None,
        "semgrep_findings": [],
        "osv_findings": [],
        "github_findings": [],
        "secrets_findings": [],
        "governance_findings": [],
        "sbom_findings": [],
        "iac_findings": [],
        "iac_scan_skipped": False,
        "_mapper_run_count": 0,
        "cicd_findings": [],
        "data_classification_findings": [],
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


# ── Async audit with progress tracking ───────────────────────────────────

NODE_NAMES = set(ALL_NODES)
AUDIT_TTL = 600  # 10 min before stale audits get cleaned


@router.post("/audit/start")
async def audit_start(request: AuditRequest):
    """Start an asynchronous audit. Returns audit_id for progress polling."""
    repo_url = request.repo_url

    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY is not configured.",
        )

    audit_id = str(uuid.uuid4())[:8]
    create_audit(audit_id)

    # Launch background task
    asyncio.create_task(_run_audit_with_progress(audit_id, repo_url))

    return {
        "audit_id": audit_id,
        "repo_url": repo_url,
        "graph_nodes": ALL_NODES,
    }


@router.get("/audit/{audit_id}/status")
async def audit_progress(audit_id: str):
    """Poll the current node-level execution status for an audit."""
    status = get_status(audit_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return status


@router.get("/audit/{audit_id}/results")
async def audit_results(audit_id: str):
    """Get the final results for a completed audit."""
    status = get_status(audit_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Audit not found")

    if status["status"] == "running":
        raise HTTPException(status_code=409, detail="Audit is still running")

    result = get_result(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Results not available")

    # Clean up after returning results
    asyncio.create_task(_delayed_cleanup(audit_id))
    return JSONResponse(content=result, headers={"X-Cache": "MISS"})


async def _run_audit_with_progress(
    audit_id: str, repo_url: str, *, local_path: str | None = None
) -> None:
    """Run the compliance graph and track node-level completion progress.

    Uses LangGraph's astream(stream_mode="updates"). Each chunk is
    {"node_name": {"field": "value", ...}} — emitted when a node finishes.
    The frontend animates the "running" state based on graph topology.
    """
    from app.utils.git import SOURCE_ZIP, detect_source_type, parse_git_url

    source_type = detect_source_type(repo_url)
    if source_type == SOURCE_ZIP:
        source_type = "zip"
    _, repo_name, _ = parse_git_url(repo_url)
    if not repo_name:
        repo_name = "repo"

    initial_state: AuditState = {
        "repo_url": repo_url,
        "local_path": local_path,
        "input_source": source_type,
        "repo_name": repo_name,
        "semgrep_findings": [],
        "osv_findings": [],
        "github_findings": [],
        "secrets_findings": [],
        "governance_findings": [],
        "sbom_findings": [],
        "iac_findings": [],
        "iac_scan_skipped": False,
        "_mapper_run_count": 0,
        "cicd_findings": [],
        "data_classification_findings": [],
        "mapped_controls": [],
        "report": "",
        "error": None,
    }

    final_state: AuditState = dict(initial_state)

    try:
        # Mark orchestrator as running immediately
        mark_running(audit_id, "orchestrator")

        async for event in compliance_graph.astream(
            initial_state,
            stream_mode="updates",
        ):
            if not isinstance(event, dict):
                logger.debug("Audit %s non-dict event: %s", audit_id, type(event).__name__)
                continue

            for node_name, update in event.items():
                if node_name not in NODE_NAMES:
                    continue
                if not isinstance(update, dict):
                    continue

                logger.debug("Audit %s node completed: %s (keys: %s)",
                             audit_id, node_name, list(update.keys()))
                # Node just finished — mark completed
                mark_completed(audit_id, node_name)
                # Merge update into our accumulated final state
                final_state.update(update)

        logger.info("Audit %s stream ended, final_state keys: %s",
                     audit_id, list(final_state.keys()))

    except Exception as exc:
        logger.error("Audit %s streaming failed: %s", audit_id, exc)
        complete_audit(audit_id, str(exc))
        return

    # --- Determine final result ---
    try:
        report_str = final_state.get("report", "")
        logger.info("Audit %s post-stream: report_str length=%d, have %d mapped_controls",
                     audit_id, len(report_str) if report_str else 0,
                     len(final_state.get("mapped_controls", [])))

        if report_str:
            report_json = json.loads(report_str)
        elif final_state.get("semgrep_findings") is not None:
            # astream terminated before compliance_mapper/report_generator.
            # Run them manually against the accumulated state.
            logger.info("Audit %s running offline mapper+report", audit_id)
            mapper_result = await run_compliance_mapper(final_state)
            final_state.update(mapper_result)
            mark_completed(audit_id, "compliance_mapper")

            report_result = await run_report_generator(final_state)
            final_state.update(report_result)
            mark_completed(audit_id, "report_generator")
            report_str = final_state.get("report", "")

            if report_str:
                report_json = json.loads(report_str)
            else:
                error = final_state.get("error") or "No results produced"
                logger.warning("Audit %s offline report failed: %s", audit_id, error)
                complete_audit(audit_id, error)
                return
        else:
            error = final_state.get("error") or "No results produced"
            logger.warning("Audit %s no findings or report, error=%s", audit_id, error)
            complete_audit(audit_id, error)
            return

        # Save and cache the report
        cache_key = await get_cache_key(repo_url)
        await save_cached_report(cache_key, report_json)
        save_result(audit_id, report_json)
        error = final_state.get("error")
        complete_audit(audit_id, error)
    except Exception as exc:
        logger.error("Audit %s result processing failed: %s", audit_id, exc)
        complete_audit(audit_id, str(exc))

    # ── Cleanup cloned repo ──────────────────────────────────────────────
    local_path = final_state.get("local_path")
    if local_path:
        await cleanup_repo(local_path)


async def _delayed_cleanup(audit_id: str) -> None:
    """Remove audit tracking data after a delay."""
    await asyncio.sleep(AUDIT_TTL)
    cleanup(audit_id)


# ── Static node list endpoint ────────────────────────────────────────────


@router.get("/audit/status")
async def audit_status():
    return {"status": "ready", "graph_nodes": ALL_NODES}


# ── ZIP upload endpoint ─────────────────────────────────────────────────


@router.post("/audit/upload")
async def audit_upload(file: UploadFile = File(...)):
    """Upload a ZIP of a repository to audit."""
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    try:
        zip_data = await file.read()
        local_path = await extract_zip(zip_data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to extract ZIP: {exc}")

    repo_name = (file.filename or "upload").removesuffix(".zip").removesuffix(".ZIP")
    repo_url = f"zip://{repo_name}"

    audit_id = str(uuid.uuid4())[:8]
    create_audit(audit_id)

    asyncio.create_task(
        _run_audit_with_progress(audit_id, repo_url, local_path=local_path)
    )

    return {"audit_id": audit_id, "repo_url": repo_url, "repo_name": repo_name}


# ──

    return {"audit_id": audit_id, "repo_url": repo_url, "repo_name": repo_name}
