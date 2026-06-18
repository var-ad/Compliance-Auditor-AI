import logging
import shutil

from app.graph.state import AuditState
from app.utils.git import _find_git, clone_repo

logger = logging.getLogger(__name__)


async def orchestrate(state: AuditState) -> dict:
    repo_url = state["repo_url"]
    if not (
        repo_url.startswith("https://github.com")
        or repo_url.startswith("git@github.com")
    ):
        return {"error": "Invalid GitHub repo URL. Only GitHub repositories are supported."}

    # Check git is available before attempting clone
    git_path = shutil.which("git")
    if not git_path:
        try:
            git_path = _find_git()
        except RuntimeError as e:
            return {"error": str(e)}

    try:
        local_path = await clone_repo(repo_url)
        logger.info("Repository cloned successfully")
        return {"local_path": local_path}
    except Exception as e:
        err_text = str(e) or "Unknown error (empty exception)"
        logger.error("Clone failed for %s (exit check: git=%s): %s", repo_url, git_path, err_text)
        return {"error": f"Failed to clone repository: {err_text}"}
