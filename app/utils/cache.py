import hashlib
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.utils.config import GITHUB_TOKEN, SUPABASE_KEY, SUPABASE_URL
from app.utils.git import SOURCE_GITHUB, detect_source_type, parse_git_url

logger = logging.getLogger(__name__)

CACHE_TTL = timedelta(hours=24)
FALLBACK_TTL = timedelta(minutes=5)  # shorter TTL when SHA can't be resolved
FALLBACK_PREFIX = "fb_"


async def get_cache_key(repo_url: str) -> str:
    """Generate a cache key based on commit SHA (GitHub) or URL hash (others)."""
    source_type = detect_source_type(repo_url)

    # GitHub: use latest commit SHA for cache-busting
    if source_type == SOURCE_GITHUB:
        try:
            owner, repo, _ = parse_git_url(repo_url)
            if owner and repo:
                headers = {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if GITHUB_TOKEN:
                    headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

                async with httpx.AsyncClient(timeout=15) as client:
                    response = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD",
                        headers=headers,
                    )
                    if response.status_code == 200:
                        sha = response.json().get("sha", "")
                        if sha:
                            return f"{owner}_{repo}_{sha}"
        except Exception:
            pass

    # Fallback: hash the URL/path for non-GitHub sources
    return FALLBACK_PREFIX + _fallback_key(repo_url)


def _fallback_key(repo_url: str) -> str:
    return hashlib.md5(repo_url.encode()).hexdigest()


def _get_supabase():
    """Get a Supabase client, or None if not configured."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_KEY)


async def get_cached_report(key: str) -> dict | None:
    """Retrieve a cached report if it exists and is fresh."""
    try:
        supabase = _get_supabase()
        if supabase is None:
            return None

        ttl = FALLBACK_TTL if key.startswith(FALLBACK_PREFIX) else CACHE_TTL

        response = supabase.table("audit_cache").select("*").eq("cache_key", key).execute()

        if not response.data:
            return None

        row = response.data[0]
        created_at = row.get("created_at")
        if created_at:
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - created_at
            if age > ttl:
                return None

        return row.get("report")
    except Exception as exc:
        logger.debug("Cache lookup failed: %s", exc)
        return None


async def save_cached_report(key: str, report: dict) -> None:
    """Save a report to the audit cache."""
    try:
        supabase = _get_supabase()
        if supabase is None:
            return

        supabase.table("audit_cache").upsert(
            {
                "cache_key": key,
                "report": report,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ).execute()
        logger.info("Cached report for key %s", key)
    except Exception as exc:
        logger.debug("Failed to cache report: %s", exc)


async def purge_stale_cache() -> int:
    """Remove cache entries older than their respective TTL. Returns count of purged rows."""
    try:
        supabase = _get_supabase()
        if supabase is None:
            return 0

        now = datetime.now(timezone.utc)
        # Purge regular entries older than CACHE_TTL
        cutoff = (now - CACHE_TTL).isoformat()
        response = (
            supabase.table("audit_cache")
            .delete()
            .lt("created_at", cutoff)
            .execute()
        )
        count = len(response.data) if response.data else 0
        if count:
            logger.info("Purged %d stale cache entries", count)
        return count
    except Exception as exc:
        logger.debug("Cache purge failed: %s", exc)
        return 0
