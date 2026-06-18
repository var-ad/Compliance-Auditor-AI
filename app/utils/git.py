import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def parse_github_url(repo_url: str) -> tuple[str | None, str | None]:
    """Parse a GitHub URL into (owner, repo) tuple.

    Supports https://github.com/owner/repo and git@github.com:owner/repo formats.
    Returns (None, None) for invalid or non-GitHub URLs.
    """
    ssh_match = re.match(
        r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$", repo_url
    )
    if ssh_match:
        return ssh_match.group("owner"), ssh_match.group("repo")

    parsed = urlparse(repo_url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != "github.com":
        return None, None
    parts = [
        part
        for part in parsed.path.strip("/").removesuffix(".git").split("/")
        if part
    ]
    if len(parts) != 2:
        return None, None
    return parts[0], parts[1]


def _find_git() -> str:
    """Find the git executable path."""
    git_path = shutil.which("git")
    if git_path:
        return git_path
    # Common Windows locations as fallback
    for candidate in [
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\bin\git.exe",
        os.path.expanduser("~/scoop/shims/git.exe"),
        os.path.expanduser("~/AppData/Local/Programs/Git/bin/git.exe"),
    ]:
        if os.path.isfile(candidate):
            return candidate
    raise RuntimeError(
        "git is not installed or not on PATH. "
        "Install git from https://git-scm.com/ and ensure it's on PATH."
    )


def _clone_sync(repo_url: str, tmp_dir: str, git_path: str) -> str:
    """Synchronous git clone — runs in a thread via asyncio.to_thread."""
    result = subprocess.run(
        [git_path, "clone", "--depth", "1", repo_url, tmp_dir],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        err = result.stderr.decode(errors="replace") if result.stderr else ""
        out = result.stdout.decode(errors="replace") if result.stdout else ""
        detail = err.strip() or out.strip() or f"git clone failed (exit code {result.returncode})"
        raise RuntimeError(detail)
    return tmp_dir


async def clone_repo(repo_url: str) -> str:
    """Clone a git repo to a temporary directory and return the path."""
    git_path = _find_git()
    tmp_dir = tempfile.mkdtemp()
    logger.debug("Cloning into %s", tmp_dir)

    await asyncio.to_thread(_clone_sync, repo_url, tmp_dir, git_path)

    logger.info("Cloned %s successfully", repo_url)
    return tmp_dir


async def cleanup_repo(path: str) -> None:
    """Remove a temporary repository directory."""
    if path:
        shutil.rmtree(path, ignore_errors=True)
        logger.debug("Cleaned up temp dir")
