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
