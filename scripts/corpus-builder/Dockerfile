FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY shared/ ./shared/
RUN pip install --no-cache-dir ./shared

COPY scripts/corpus-builder/requirements.txt ./corpus-builder/requirements.txt
RUN pip install --no-cache-dir -r ./corpus-builder/requirements.txt

COPY scripts/corpus-builder/ ./corpus-builder/
COPY agents/llm_provider.py ./agents/llm_provider.py
COPY agents/__init__.py ./agents/__init__.py

RUN pip install --no-cache-dir -e ./shared

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENV QDRANT_HOST=qdrant
ENV QDRANT_PORT=6333
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV EMBEDDING_PROVIDER=ollama
ENV EMBEDDING_MODEL=nomic-embed-text
ENV CORPUS_DAYS=7

RUN useradd -r -s /bin/false appuser
USER appuser

CMD ["python", "corpus-builder/build_corpus.py"]
