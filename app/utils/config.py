"""Central configuration for the compliance auditor.

load_dotenv() is called exactly once here, at import time.
All other modules import env vars from this module instead of calling load_dotenv.
"""

import os

from dotenv import load_dotenv

load_dotenv()

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
