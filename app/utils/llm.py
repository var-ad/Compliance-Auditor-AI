"""LLM utility helpers."""

import asyncio
import logging
import re

logger = logging.getLogger(__name__)


def strip_markdown_fences(content: str) -> str:
    """Strip markdown code fences (```json ... ```) around a JSON response."""
    if content.startswith("```"):
        # Remove opening fence line (```json, ```, etc.)
        content = content.split("\n", 1)[-1]
        # Remove closing fence line
        content = content.rsplit("\n", 1)[0]
        # Handle edge case where ``` is on same line as last content
        if content.endswith("```"):
            content = content[:-3]
    return content


async def groq_retry(coro_factory, max_retries=5, base_delay=1.0):
    """Call a Groq API coroutine, retrying on 429 rate limits with exponential backoff.

    Args:
        coro_factory: Async callable that returns an API response.
        max_retries: Maximum number of retries on 429.
        base_delay: Initial delay in seconds (doubles each retry).

    Returns:
        The API response on success.

    Raises:
        The last exception if all retries are exhausted or the error is not a 429.
    """
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            status = _extract_status(exc)
            if status != 429 or attempt >= max_retries:
                raise

            # Extract Retry-After from error message if present
            delay = _parse_retry_after(str(exc)) or (base_delay * (2**attempt))
            logger.info(
                "Groq rate limited (attempt %d/%d), retrying in %.1fs",
                attempt + 1,
                max_retries,
                delay,
            )
            await asyncio.sleep(delay)

    raise last_exc


def _extract_status(exc: Exception) -> int | None:
    """Try to extract HTTP status code from a Groq API exception."""
    # Some API clients set status_code directly
    status = getattr(exc, "status_code", None)
    if status is not None:
        return int(status)
    # Fallback: parse from error message "Error code: 429"
    msg = str(exc)
    match = re.search(r"Error code: (\d+)", msg)
    if match:
        return int(match.group(1))
    return None


def _parse_retry_after(message: str) -> float | None:
    """Parse 'try again in 1m15.168s' from a rate limit error message."""
    match = re.search(r"try again in ([\d.]+)s", message)
    if match:
        return float(match.group(1))
    match = re.search(r"try again in ([\d.]+)m([\d.]+)s", message)
    if match:
        return float(match.group(1)) * 60 + float(match.group(2))
    return None
