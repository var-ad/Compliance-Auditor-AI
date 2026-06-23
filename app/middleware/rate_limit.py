import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter for audit-creation endpoints.

    Limits each IP to RATE_LIMIT requests per WINDOW_SECONDS.
    Periodically purges stale entries to prevent unbounded memory growth.
    """

    RATE_LIMIT = 10
    WINDOW_SECONDS = 60
    CLEANUP_THRESHOLD = 1000  # purge all IPs when tracked IPs exceed this
    AUDIT_CREATION_PATHS = {
        "/api/audit",
        "/api/audit/start",
        "/api/audit/upload",
        "/api/audit/local",
    }

    def __init__(self, app):
        super().__init__(app)
        self._requests: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        if (
            request.url.path in self.AUDIT_CREATION_PATHS
            and request.method == "POST"
        ):
            client_ip = request.client.host if request.client else "unknown"
            now = time.time()
            window_start = now - self.WINDOW_SECONDS

            # Periodic global cleanup when dict grows large
            if len(self._requests) > self.CLEANUP_THRESHOLD:
                self._global_purge(window_start)

            timestamps = self._requests.setdefault(client_ip, [])
            # Purge old entries for this IP
            self._requests[client_ip] = [t for t in timestamps if t > window_start]

            if len(self._requests[client_ip]) >= self.RATE_LIMIT:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded. "
                        f"Max {self.RATE_LIMIT} requests per {self.WINDOW_SECONDS}s."
                    },
                )

            self._requests[client_ip].append(now)

        return await call_next(request)

    def _global_purge(self, cutoff: float) -> None:
        """Remove IPs that have no requests within the window."""
        self._requests = {
            ip: ts
            for ip, ts in self._requests.items()
            if any(t > cutoff for t in ts)
        }
