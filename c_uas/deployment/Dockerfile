# syntax=docker/dockerfile:1
# Multi-stage build for the C-UAS platform API.
# Stage 1 (builder): install dependencies into a venv.
# Stage 2 (runtime): slim image, non-root user, runs the API server.
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY . ./

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install .

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    CUAS_API_HOST=0.0.0.0 \
    CUAS_API_PORT=8000

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

# Run as a non-root user (uid/gid 10001 dynamically allocated by adduser).
RUN groupadd -r c-uas && useradd -r -g c-uas c-uas
USER c-uas

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5)"

CMD ["c-uas", "api", "--host", "0.0.0.0", "--port", "8000"]
