# AI Agent Layer

Three LangGraph agents that consume vulnerability match events from Kafka, gather evidence through deterministic tool calls and RAG retrieval, and synthesise structured reports using an LLM. Designed to work well with a small local model (Ollama `qwen2.5-coder:7b`) by restricting LLM invocations to final synthesis steps over pre-gathered, structured evidence.

---

## Design principle: evidence first, LLM last

Each agent gathers all relevant facts first through deterministic tool calls — actual source code, actual CVE records, actual version ranges — and only then asks the LLM to reason over what's in front of it. The LLM acts as a structured synthesis engine, not an oracle.

```
Kafka event
    │
    ▼
Node 1: RAG retrieval ──────────────── deterministic
Node 2: GitHub code fetch ──────────── deterministic
Node 3: LLM exploitability assessment  ← LLM call 1
Node 4: OSV + deps.dev lookup ──────── deterministic
Node 5: LLM report synthesis ────────  ← LLM call 2
    │
    ▼
TriageReport → PostgreSQL
```

---

## Running in Docker

The triage agent runs as a long-lived Kafka consumer container. It requires Ollama (or Anthropic API access) to be available.

### Start the agent

```bash
# Start infrastructure + Ollama + pull models, then start the agent
make infra-up
make agents-up
```

`make agents-up` starts Ollama, waits for it to be healthy, triggers model pulls (`qwen2.5-coder:7b` and `nomic-embed-text`), then starts the triage agent and MCP server.

Or start just the triage agent after the infrastructure is running:

```bash
docker compose -f infrastructure/docker-compose.yml up -d triage-agent
```

### Watch the logs

```bash
make logs s=triage-agent

# Directly
docker compose -f infrastructure/docker-compose.yml logs -f triage-agent
```

A successful processing cycle looks like:

```
{"service":"triage-agent","level":"info","event":"processing match","cve_id":"CVE-2024-35195","service_id":"checkout-api"}
{"service":"triage-agent","level":"info","event":"rag retrieval complete","results":5}
{"service":"triage-agent","level":"info","event":"code fetch complete","files_found":2}
{"service":"triage-agent","level":"info","event":"exploitability assessed","verdict":"CONFIRMED"}
{"service":"triage-agent","level":"info","event":"triage report written","report_id":"rpt-abc123"}
```

### Inject a test event

You can test the agent without the full Flink pipeline running by publishing a match event directly to Kafka:

```bash
# Publish a test match event via the Redpanda container
docker compose -f infrastructure/docker-compose.yml exec redpanda \
  rpk topic produce vuln.matches.critical --brokers localhost:9092 << 'JSON'
{"match_id":"test-01","cve_id":"CVE-2024-35195","service_id":"checkout-api","matched_package":"requests","matched_version":"2.28.0","cvss_score":5.9,"severity_tier":"MEDIUM","blast_radius_tier":"CRITICAL","ecosystem":"pypi","detected_at":"2024-01-15T10:00:00Z"}
JSON
```

Or use the Redpanda Console at [http://localhost:8080](http://localhost:8080) → Topics → `vuln.matches.critical` → **Produce message**.

### Rebuild after code changes

```bash
make rebuild s=triage-agent
```

### Open a shell inside the container

```bash
make shell s=triage-agent

# Useful inside the shell:
python -c "from agents.triage.agent import triage_graph; print('imports OK')"
env | grep LLM
```

---

## Switching between Ollama, Groq, and Claude

All agents import their LLM from `llm_provider.py`. Change one variable — either in `.env` or in the `triage-agent` environment block in `infrastructure/docker-compose.yml`:

```bash
# Option 1 — Local development (default, needs ~5GB RAM for the model)
LLM_PROVIDER=ollama
LLM_MODEL=qwen2.5-coder:7b-instruct-q4_K_M
EMBEDDING_PROVIDER=ollama
EMBEDDING_MODEL=nomic-embed-text

# Option 2 — Groq (free remote inference, saves laptop RAM, no GPU needed)
# Sign up free at https://console.groq.com to get an API key.
# Groq has no embeddings API — Ollama still handles embeddings locally,
# but since the model is small (nomic-embed-text, ~270MB) this is fine.
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile   # or: mixtral-8x7b-32768, gemma2-9b-it
EMBEDDING_PROVIDER=ollama             # Groq has no embeddings endpoint

# Option 3 — Production (Anthropic Claude, paid)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
EMBEDDING_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

No agent file needs to change. `llm_provider.py` provides `get_llm()` and `get_embeddings()` — nothing else in the agent layer imports from `langchain_ollama`, `langchain_groq`, or `langchain_anthropic` directly.

Note that `EMBEDDING_PROVIDER` is now independent of `LLM_PROVIDER`. This is intentional — Groq has no embeddings API, so you set `LLM_PROVIDER=groq` for chat and `EMBEDDING_PROVIDER=ollama` for embeddings simultaneously.

---

## `llm_provider.py`

The single file all agents import from. Returns a `BaseChatModel` or `Embeddings` instance based on `LLM_PROVIDER`. Nothing else imports from `langchain_ollama` or `langchain_anthropic` directly.

```python
from agents.llm_provider import get_llm, get_embeddings

llm = get_llm(temperature=0.0)
embeddings = get_embeddings()
```

---

## Triage Agent — `triage/`

Processes `CRITICAL` and `HIGH` vulnerability match events. Produces a `TriageReport` per event.

### Graph nodes

**Node 1 — `retrieve_cve_context`**
Embeds a query and searches two Qdrant collections: `cve_descriptions` and `exploit_reports`. Returns the top 5 most relevant passages.

**Node 2 — `fetch_affected_files`**
Calls the GitHub Search API to find files in the affected service's repository that import the vulnerable package. Fetches the first 2,000 characters of each file.

**Node 3 — `assess_exploitability`** *(LLM call)*
Prompts the LLM with CVE context and source files. Returns a structured JSON verdict: `CONFIRMED`, `LIKELY`, `UNLIKELY`, or `NOT_AFFECTED`. If `NOT_AFFECTED`, the graph short-circuits — no report is written, no alert fires.

**Node 4 — `fetch_remediation_path`**
Calls OSV.dev for the safe version. Calls deps.dev to check for breaking changes. No LLM involved.

**Node 5 — `generate_triage_report`** *(LLM call)*
Prompts the LLM with all gathered evidence and asks it to produce a structured `TriageReport` JSON.

### Output written to PostgreSQL `triage_reports`:

```json
{
  "report_id": "rpt-abc123",
  "cve_id": "CVE-2024-35195",
  "service_id": "checkout-api",
  "generated_at": "2024-05-20T09:35:00Z",
  "exploitability_verdict": "CONFIRMED",
  "exploitability_rationale": "checkout-api/src/http_client.py line 47 calls requests.get() with user-supplied URLs...",
  "blast_radius_tier": "CRITICAL",
  "blast_radius_rationale": "checkout-api is customer-facing and PCI DSS in scope.",
  "remediation_action": "pip install requests==2.32.1",
  "safe_version": "2.32.1",
  "is_breaking_change": false,
  "estimated_effort_hours": 0.5,
  "sla_deadline": "2024-05-20T13:35:00Z",
  "assigned_team": "payments",
  "confidence_score": 0.87
}
```

### `triage/consumer.py`

Kafka consumer subscribed to `vuln.matches.critical` and `vuln.matches.high`. Commits the Kafka offset only after the report is successfully written to PostgreSQL — no events are lost if the database write fails.

---

## PR Risk Agent — `pr_risk/agent.py`

Consumes events from `deps.risk.prs` — emitted by the Flink router when a `DependencyChangeEvent` adds a new package rather than bumping an existing one.

**Assessment steps:**
1. Query OSV.dev for known vulnerabilities at the proposed version
2. Check deps.dev for maintenance signals (last release, maintainer count, open issues)
3. Check for major version incompatibilities with existing dependencies
4. LLM synthesis → APPROVE / WARN / BLOCK verdict

**Output:** Posts a structured PR review comment to GitHub via the API.

---

## Posture Agent — `posture/agent.py`

A scheduled agent (daily at 06:00 UTC) that queries PostgreSQL directly and produces an executive security summary — no Kafka consumption.

Report includes open counts by tier, SLA breach count, MTTD/MTTR over 30 days, per-team exposure, compliance gap summary, and an LLM-generated executive narrative. Written to PostgreSQL `posture_reports` and to MinIO as JSON.

---

## RAG Retriever — `rag/retriever.py`

| Collection | Contents | Indexed by |
|---|---|---|
| `cve_descriptions` | CVE descriptions and summaries | `scripts/corpus-builder/` |
| `exploit_reports` | Public exploit POC summaries | `scripts/corpus-builder/` |
| `triage_reports` | Past triage report text | Triage consumer (written automatically) |

---

## Environment variables

| Variable | Default (in container) | Description |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | `ollama`, `groq`, or `anthropic` |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b-instruct-q4_K_M` | Chat model (Ollama only) |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | `ollama:11434` in Docker, `localhost:11434` from host |
| `GROQ_API_KEY` | — | Required if `LLM_PROVIDER=groq`. Free at console.groq.com |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model. Also: `mixtral-8x7b-32768`, `gemma2-9b-it` |
| `ANTHROPIC_API_KEY` | — | Required if `LLM_PROVIDER=anthropic` |
| `EMBEDDING_PROVIDER` | `ollama` | `ollama` or `openai`. Independent of `LLM_PROVIDER` |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model (Ollama only) |
| `OPENAI_API_KEY` | — | Required if `EMBEDDING_PROVIDER=openai` |
| `POSTGRES_URL` | `postgresql://appsec:appsec@postgres:5432/appsec` | `postgres` in Docker, `localhost` from host |
| `QDRANT_HOST` | `qdrant` | `qdrant` in Docker, `localhost` from host |
| `QDRANT_PORT` | `6333` | — |
| `KAFKA_BROKERS` | `redpanda:9092` | `redpanda:9092` in Docker, `localhost:9092` from host |
| `GITHUB_TOKEN` | — | Required for code fetch tool in triage agent |
