# =============================================================================
# Compliance Auditor — OCI-optimized multi-stage Dockerfile
# =============================================================================
# OCI Container Instances / OKE best practices:
#   - Multi-stage build for minimal final image
#   - Non-root user
#   - Proper signal handling (PID 1)
#   - Health check for OCI load balancer
#   - ARM-compatible (Ampere A1) via python:3.11-slim multi-arch
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: build — install runtime dependencies
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS build

WORKDIR /app

# Install uv (fast package manager)
RUN pip install --no-cache-dir uv==0.9.17

# Copy dependency manifests first for Docker layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies into a system path
RUN uv sync --no-dev --no-install-project

# ---------------------------------------------------------------------------
# Stage 2: runtime — minimal final image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# OCI best practice: create a non-root user
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy installed packages from build stage
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY pyproject.toml .

# Ensure scripts are executable
RUN chmod -R a+r app/ scripts/

# OCI Container Instances often expect 8080 as the default HTTP port
EXPOSE 8080

# Switch to non-root user
USER appuser

# Health check — OCI load balancers poll this endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health', timeout=5).raise_for_status()" || exit 1

# Use exec form for proper signal handling (PID 1)
# Bind to 0.0.0.0:8080 (OCI standard port)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
