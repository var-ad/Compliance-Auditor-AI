"""Central configuration for the compliance auditor.

load_dotenv() is called exactly once here, at import time.
All other modules import env vars from this module instead of calling load_dotenv.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _csv_env(name: str, default: str) -> list[str]:
    """Read a comma-separated environment variable into a clean list."""
    return [
        value.strip()
        for value in os.getenv(name, default).split(",")
        if value.strip()
    ]


# LLM
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# GitHub
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Auth
AUDIT_API_KEY = os.getenv("AUDIT_API_KEY", "")

# HTTP / deployment
CORS_ORIGINS = _csv_env(
    "CORS_ORIGINS",
    "https://complianceauditor.varad.fyi,http://localhost:5173",
)
CORS_ORIGIN_REGEX = os.getenv("CORS_ORIGIN_REGEX", "").strip() or None
ALLOWED_HOSTS = _csv_env(
    "ALLOWED_HOSTS",
    "auditor.varad.fyi,localhost,127.0.0.1",
)
