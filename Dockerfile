# Small, non-root, read-only-friendly image. Scanned by Trivy in CI.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
# Pull in Debian security fixes newer than the base image (Trivy gate fails on fixable HIGH/CRITICAL)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt && useradd --uid 10001 --no-create-home tripwire
COPY tripwire tripwire
COPY policy policy
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
ENV TRIPWIRE_LOG=/tmp/logs/decisions.jsonl
CMD ["uvicorn", "--factory", "tripwire.gateway:default_app", "--host", "0.0.0.0", "--port", "8080"]
