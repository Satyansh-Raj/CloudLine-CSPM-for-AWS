# ---- Build stage ----
FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install ".[dev]"

# ---- Production stage ----
FROM python:3.11-slim

LABEL maintainer="CloudLine <cloudline@dev>"
LABEL description="CloudLine backend — OPA-based AWS misconfiguration detector"

# Install curl for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY app/ ./app/
COPY tests/ ./tests/
COPY pyproject.toml .

# Install the package itself (editable)
RUN pip install --no-cache-dir -e .

# Non-root user
RUN groupadd -r cloudline && \
    useradd -r -g cloudline -d /app cloudline && \
    chown -R cloudline:cloudline /app
USER cloudline

EXPOSE 9710

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9710/health || exit 1

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "9710"]
