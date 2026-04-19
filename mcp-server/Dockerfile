FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

COPY shared/ ./shared/
RUN pip install --no-cache-dir ./shared

COPY mcp-server/requirements.txt ./mcp-server/requirements.txt

COPY agents/requirements.txt ./agents/requirements.txt
RUN pip install --no-cache-dir \
    -r ./mcp-server/requirements.txt \
    -r ./agents/requirements.txt


FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

COPY shared/ ./shared/
COPY agents/ ./agents/
COPY mcp-server/ ./mcp_server/

RUN pip install --no-cache-dir -e ./shared

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENV POSTGRES_URL=postgresql://appsec:appsec@postgres:5432/appsec
ENV QDRANT_HOST=qdrant
ENV QDRANT_PORT=6333
ENV REDIS_URL=redis://redis:6379
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV EMBEDDING_PROVIDER=ollama
ENV EMBEDDING_MODEL=nomic-embed-text

EXPOSE 8000

RUN useradd -r -s /bin/false appuser
USER appuser

CMD ["python", "mcp_server/server.py"]
