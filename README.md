# Compliance Auditor AI

Automated compliance auditing for GitHub repositories using SAST scanning, dependency vulnerability analysis, and multi-framework compliance mapping.

## Architecture

```
FastAPI → LangGraph (6-node state machine) → Groq (LLM) + Supabase (Vector DB)
                                          → Semgrep + OSV-Scanner + GitHub API
```

The audit pipeline is a **LangGraph state machine** with these stages:

| Node | Tool | What it checks |
|------|------|---------------|
| orchestrator | — | Validates URL, clones repo |
| semgrep | Semgrep | Static analysis (SAST) for code issues |
| osv | OSV-Scanner | Open-source dependency vulnerabilities |
| github | GitHub API | MFA enforcement, branch protection, repo visibility |
| compliance_mapper | Groq LLM + Supabase pgvector | Maps findings to SOC2, ISO27001, GDPR, DPDP |
| report_generator | Groq LLM | Computes weighted score, generates executive summary |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (package manager)
- `semgrep` and `osv-scanner` on PATH
- Git

### Setup

```bash
# Clone and enter the project
cd compliance-auditor

# Create .env from template
cp .env.example .env
# Edit .env with your API keys

# Sync dependencies
uv sync

# Run the API server
uv run uvicorn app.main:app --reload
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GROQ_API_KEY` | Yes | Groq API key for LLM calls |
| `GITHUB_TOKEN` | No | GitHub token (higher rate limits, private repos) |
| `SUPABASE_URL` | No | Supabase project URL (for GDPR/DPDP RAG + caching) |
| `SUPABASE_KEY` | No | Supabase service role key |
| `AUDIT_API_KEY` | No | API key for incoming requests (empty = dev mode) |
| `LLM_MODEL` | No | Groq model name (default: `llama-3.3-70b-versatile`) |

### Database Setup (Optional)

For GDPR/DPDP RAG mapping and audit result caching:

1. Create a Supabase project and enable the pgvector extension
2. Run the schema from `scripts/setup_supabase.sql`
3. Populate compliance documents:
   ```bash
   uv run python scripts/embed_documents.py
   ```

## API

### `POST /api/audit`

Run a full compliance audit on a public GitHub repository.

```json
// Request
{"repo_url": "https://github.com/fastapi/fastapi"}

// Response
{
  "repo_url": "https://github.com/fastapi/fastapi",
  "overall_score": 72,
  "executive_summary": "...",
  "framework_scores": {"soc2": 65, "iso27001": 70, "gdpr": 80, "dpdp": 90},
  "frameworks": {...},
  "severity_breakdown": {"critical": 1, "high": 2, "medium": 5, "low": 3}
}
```

### `GET /api/audit/status`

Returns the current graph node list.

### `GET /health`

Health check (no auth required).

## Scoring Model

Compliance scores are computed per framework, then blended:

| Framework | Weight | Severity Deductions |
|-----------|--------|---------------------|
| SOC2 | 35% | critical: -25, high: -15, medium: -7, low: -3 |
| ISO27001 | 25% | same scale |
| GDPR | 25% | same scale |
| DPDP | 15% | same scale |

Per-framework: `score = max(0, 100 + sum(severity_deductions))`
Overall: `weighted_average(per_framework_scores)`

## Compliance Frameworks

- **SOC2** — Trust Services Criteria (CC6.x, CC7.x, CC8.x)
- **ISO27001** — Annex A controls (A.9, A.10, A.12, A.14)
- **GDPR** — EU General Data Protection Regulation (via RAG on EUR-Lex articles)
- **DPDP** — India's Digital Personal Data Protection Act 2023 (via RAG on official PDF)

## Project Structure

```
app/
├── main.py                     # FastAPI entry point
├── middleware/
│   ├── auth.py                 # API key authentication
│   └── rate_limit.py           # In-memory rate limiter
├── routers/
│   └── audit.py                # Audit API endpoints
├── graph/
│   ├── graph.py                # LangGraph state machine definition
│   ├── state.py                # TypedDicts for state
│   └── nodes/                  # Individual pipeline nodes
├── mapper/
│   ├── controls.py             # SOC2/ISO27001 control mapping
│   └── rag_mapper.py           # GDPR/DPDP RAG retrieval
└── utils/
    ├── config.py               # Central env configuration
    ├── git.py                  # Repo clone/cleanup utilities
    └── cache.py                # Audit result caching
scripts/
├── setup_supabase.sql          # Database schema
├── embed_documents.py          # Populate vector store
├── test_end_to_end.py          # Integration test
└── test_tools.py               # Environment check
```
