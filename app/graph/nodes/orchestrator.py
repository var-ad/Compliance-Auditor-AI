import logging
import os
import shutil

from app.graph.state import AuditState
from app.utils.git import (
    SOURCE_BITBUCKET,
    SOURCE_GENERIC_GIT,
    SOURCE_GITHUB,
    SOURCE_GITLAB,
    SOURCE_ZIP,
    _find_git,
    clone_repo,
    detect_source_type,
    parse_git_url,
)

logger = logging.getLogger(__name__)


async def orchestrate(state: AuditState) -> dict:
    repo_url = state.get("repo_url", "")
    source_type = detect_source_type(repo_url)
    result: dict = {"input_source": source_type}

    # --- ZIP source is handled by the endpoint (local_path already set) ---
    if source_type == SOURCE_ZIP:
        path = state.get("local_path")
        if not path or not os.path.isdir(path):
            return {"error": "ZIP extraction path is missing or invalid."}
        owner, repo_name, _ = parse_git_url(repo_url)
        result["local_path"] = path
        result["repo_name"] = repo_name or os.path.basename(path)
        logger.info("Using extracted ZIP: %s", path)
        return result

    # --- Git clone (GitHub, GitLab, Bitbucket, or any git remote) ---
    # Validate it looks like a git URL
    if not any(repo_url.startswith(p) for p in ("http://", "https://", "git@", "ssh://")):
        return {"error": f"Unrecognized input: '{repo_url}'. Provide a git URL, local path, or upload a ZIP."}

    # Check git is available
    git_path = shutil.which("git")
    if not git_path:
        try:
            git_path = _find_git()
        except RuntimeError as e:
            return {"error": str(e)}

    try:
        local_path = await clone_repo(repo_url)
        owner, repo_name, _ = parse_git_url(repo_url)
        result["local_path"] = local_path
        result["repo_name"] = repo_name or "unknown"
        logger.info("Cloned %s (%s) successfully", source_type, repo_url)
        return result
    except Exception as e:
        err_text = str(e) or "Unknown error"
        logger.error("Clone failed for %s: %s", repo_url, err_text)
        return {"error": f"Failed to clone repository: {err_text}"}
