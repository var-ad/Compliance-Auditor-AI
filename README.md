# Compliance Auditor AI

Automated compliance auditing that scans GitHub, GitLab, Bitbucket repos (or any git URL / ZIP upload) against **SOC 2**, **ISO 27001**, **GDPR**, and **DPDP** frameworks. Runs 14 parallel scanners via a LangGraph state machine and produces per-framework scores with an enterprise findings report.

## Pipeline

```
orchestrator → fan_out → [9 parallel scanners] → scanner_merge (barrier) → compliance_mapper → report_generator
```

| Node | Tool | What it checks |
|------|------|---------------|
| orchestrator | — | Validates source, clones repo or extracts ZIP |
| semgrep | Semgrep | SAST: injections, XSS, crypto flaws, Docker misconfigs |
| osv | OSV-Scanner | Dependency vulnerabilities (CVEs) |
| github | GitHub API | Public repo, branch protection, org MFA (GitHub-only) |
| scan_secrets_pii | Gitleaks + regex | Hardcoded secrets, PII (email, phone, Aadhaar, credentials) |
| scan_repo_governance | Filesystem + API | SECURITY.md, CODEOWNERS, signed commits |
| scan_sbom_license | Syft + npm/PyPI | Copyleft licenses, stale deps with CVEs |
| scan_iac_config | Checkov | Terraform/CFN/K8s misconfigs |
| scan_cicd_security | YAML parser | Plaintext secrets, missing SAST, unsigned publishing |
| scan_data_classification | Schema parsers | Unencrypted PII fields, sensitive category data (Art. 9) |
| scanner_merge | — | Barrier: waits for all 9 branches before proceeding |
| compliance_mapper | Groq + Supabase | Maps findings to controls; deterministic CONTROL_MAP + LLM explanations |
| report_generator | Groq | Scoring, severity breakdown, grounded executive summary |

## Quick Start

```bash
# Prerequisites: Python 3.11+, uv, git, semgrep, osv-scanner
cd compliance-auditor

# Environment
cp .env.example .env
# Edit with GROQ_API_KEY (required), GITHUB_TOKEN, SUPABASE_URL/KEY (optional)

# Install + run
uv sync
uv run uvicorn app.main:app --reload
```

## Input Sources

| Source | Endpoint |
|--------|----------|
| `https://github.com/owner/repo` | `POST /api/audit/start` |
| `https://gitlab.com/group/project` | `POST /api/audit/start` |
| `https://bitbucket.org/workspace/repo` | `POST /api/audit/start` |
| Any git URL | `POST /api/audit/start` |
| ZIP upload | `POST /api/audit/upload` (multipart) |
| Local directory | `POST /api/audit/local` |

## Scoring

```
Per-framework: max(0, 100 + critical×-20 + high×-10 + medium×-3 + low×-1 + info×0)
Overall: SOC2×0.35 + ISO27001×0.25 + GDPR×0.25 + DPDP×0.15
```

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GROQ_API_KEY` | Yes | LLM inference |
| `GITHUB_TOKEN` | No | Higher rate limits, org-level checks |
| `SUPABASE_URL` | No | Cache + RAG vector store |
| `SUPABASE_KEY` | No | Supabase API key |
| `AUDIT_API_KEY` | Yes in production | Shared access key entered in the frontend |
| `CORS_ORIGINS` | Yes in production | Comma-separated allowed browser origins |
| `CORS_ORIGIN_REGEX` | No | Optional regex for Vercel preview origins |
| `ALLOWED_HOSTS` | Yes in production | Comma-separated accepted HTTP hostnames |

## OCI Deployment

The production container listens on port `8080`. On an OCI VM:

```bash
cp .env.example .env
# Fill in secrets, then:
docker compose -f compose.production.yml up -d --build
```

The compose file binds the API to `127.0.0.1:8080`. Put Nginx in front of it
using `nginx.conf.example`, create an `A` record for `auditor.varad.fyi`
pointing to the OCI public IP, and issue TLS with Certbot:

```bash
sudo certbot --nginx -d auditor.varad.fyi
```

OCI networking must allow inbound TCP `80` and `443`; port `8080` should
remain private. Production CORS defaults to
`https://complianceauditor.varad.fyi` and local Vite development.

Set `AUDIT_API_KEY` to a strong, random value on OCI. Users enter it in the
frontend, which keeps it in tab-scoped session storage and sends it as the
`X-API-Key` header. Never put this key in a `VITE_*` variable because those
values are embedded in the public frontend bundle.

## Optional CLI Tools

Missing tools log warnings but don't crash — the pipeline returns empty findings for that scanner:

| Tool | Install | Scanners affected |
|------|---------|-------------------|
| semgrep | `pip install semgrep` | SAST |
| osv-scanner | [GitHub Releases](https://github.com/google/osv-scanner) | Dependency CVEs |
| syft | [GitHub Releases](https://github.com/anchore/syft) | SBOM / license |
| checkov | `pip install checkov` | IaC config |
| gitleaks | [GitHub Releases](https://github.com/gitleaks/gitleaks) | Secrets |

## Frontend

A React dashboard is available at `../compliance-frontend/`. Run alongside the backend:

```bash
cd compliance-frontend
npm install && npm run dev
```

See its [README](../compliance-frontend/README.md) for details.
