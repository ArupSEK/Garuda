FROM golang:1.25-bookworm AS httpx-builder
ARG HTTPX_VERSION=v1.9.0
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN apt-get update && apt-get install -y --no-install-recommends nmap curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=httpx-builder /go/bin/httpx /usr/local/bin/httpx-pd
WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
COPY dashboard ./dashboard
RUN pip install --no-cache-dir .
COPY . .
RUN useradd --create-home --uid 10001 scanner && chown -R scanner:scanner /app
USER scanner
EXPOSE 8000 8501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

