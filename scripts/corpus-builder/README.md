# Corpus Builder

One-time job that bulk-loads CVE descriptions and exploit reports into Qdrant so the triage agent can do semantic search via RAG.

Run this before starting the agents for the first time, and re-run it periodically (e.g. weekly) to keep the vector index fresh.

---

## Running in Docker

The corpus builder is in the `setup` Docker Compose profile so it doesn't run automatically with `make up`. Run it explicitly:

```bash
# Qdrant and Ollama must be running first
make infra-up
docker compose -f infrastructure/docker-compose.yml up -d ollama

# Wait for Ollama to be healthy (pulls nomic-embed-text automatically via ollama-init)
# Then run the corpus builder as a one-shot job
make corpus

# Equivalent manual command
docker compose -f infrastructure/docker-compose.yml --profile setup run --rm corpus-builder
```

The container runs, indexes all documents, then exits with code 0. Progress is logged to stdout:

```
{"service":"corpus-builder","level":"info","event":"starting bulk load","ecosystems":["pypi","npm","maven","go","crates.io","rubygems"]}
{"service":"corpus-builder","level":"info","event":"indexed batch","collection":"cve_descriptions","count":500,"total":500}
{"service":"corpus-builder","level":"info","event":"indexed batch","collection":"cve_descriptions","count":500,"total":1000}
...
{"service":"corpus-builder","level":"info","event":"complete","cve_descriptions":12483,"exploit_reports":3241}
```

A full run over ~6 months of OSV data takes roughly 10–20 minutes on a laptop, depending on network speed and model inference speed.

### Rebuild the image after code changes

```bash
make rebuild s=corpus-builder
```

---

## Running without Docker (optional)

```bash
docker compose -f infrastructure/docker-compose.yml up -d qdrant ollama

pip install -r scripts/corpus-builder/requirements.txt
pip install -e ./shared

export QDRANT_HOST=localhost
export QDRANT_PORT=6333
export OLLAMA_BASE_URL=http://localhost:11434

python scripts/corpus-builder/build_corpus.py
```

---

## What it indexes

**Collection: `cve_descriptions`**
Source: OSV.dev bulk export (GCS) for ecosystems PyPI, npm, Maven, Go, crates.io, RubyGems.
Each document = one OSV record. Embedded fields: `id`, `summary`, `details`, `aliases` (CVE IDs).

**Collection: `exploit_reports`**
Source: NVD CVE 2.0 API — records with CVSS ≥ 7.0 and `vulnStatus: Analyzed`.
Each document = one CVE. Embedded fields: `id`, `descriptions[0].value`, `weaknesses`.

Both collections use the configured embedding model:
- Local: `nomic-embed-text` via Ollama
- Production: `text-embedding-3-large` via OpenAI (`EMBEDDING_PROVIDER=openai`)

---

## Re-running / incremental updates

The script checks whether each document ID already exists in Qdrant before upserting, so re-running is safe — it only indexes new records.

To force a full rebuild, delete the collections first:

```bash
docker compose -f infrastructure/docker-compose.yml exec qdrant \
  sh -c "curl -X DELETE http://localhost:6333/collections/cve_descriptions && \
         curl -X DELETE http://localhost:6333/collections/exploit_reports"

make corpus
```

---

## Environment variables

| Variable | Default (in container) | Description |
|---|---|---|
| `QDRANT_HOST` | `qdrant` | `qdrant` in Docker, `localhost` from host |
| `QDRANT_PORT` | `6333` | — |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | `ollama:11434` in Docker, `localhost:11434` from host |
| `EMBEDDING_PROVIDER` | `ollama` | `ollama` or `openai` |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model |
| `CORPUS_DAYS` | `7` | How many days of recent data to fetch (pass `0` for full history) |

---

## Troubleshooting

**Container exits immediately with connection error**
Qdrant or Ollama isn't ready yet. Check `docker compose ps` and wait for both to show `healthy`, then re-run `make corpus`.

**Slow indexing**
Normal — embedding 50k+ documents takes time. The script logs every 500 documents. If you just need RAG to work for demos, set `CORPUS_DAYS=7` (the default) to index only recent records.

**`model not found` error from Ollama**
The `ollama-init` container should pull `nomic-embed-text` automatically. If it didn't, pull it manually:
```bash
docker compose -f infrastructure/docker-compose.yml exec ollama ollama pull nomic-embed-text
```
