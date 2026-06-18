from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.utils.config import AUDIT_API_KEY


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware that checks X-API-Key header on all /api/* routes.

    Bypasses auth when AUDIT_API_KEY env var is not set (dev mode).
    Always allows /health through.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)

        if request.url.path.startswith("/api/"):
            if AUDIT_API_KEY:
                api_key = request.headers.get("X-API-Key")
                if not api_key or api_key != AUDIT_API_KEY:
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Unauthorized"},
                    )

        return await call_next(request)
