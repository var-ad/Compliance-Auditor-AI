import logging
import shutil

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# Import config first so load_dotenv() runs once
from app.utils.config import (
    ALLOWED_HOSTS,
    CORS_ORIGIN_REGEX,
    CORS_ORIGINS,
)

from app.middleware.auth import APIKeyMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.routers.audit import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ("git", "semgrep", "osv-scanner")

_missing_tools: list[str] | None = None


def check_tools() -> list[str]:
    """Check which required CLI tools are missing. Returns list of missing tools."""
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        logger.warning("Missing required tools: %s", ", ".join(missing))
    else:
        logger.info("All required CLI tools are available")
    return missing


app = FastAPI(title="Compliance Auditor")

# Check CLI tools at startup
_missing_tools = check_tools()

# Restrict host headers before requests reach application routes.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(APIKeyMiddleware)
app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

app.include_router(router, prefix="/api")


@app.get("/health")
async def health():
    """Health check with tool availability status."""
    global _missing_tools
    if _missing_tools is None:
        _missing_tools = check_tools()
    return {
        "status": "ok",
        "tools": {
            tool: (tool not in _missing_tools)
            for tool in REQUIRED_TOOLS
        },
        "missing_tools": _missing_tools,
    }
