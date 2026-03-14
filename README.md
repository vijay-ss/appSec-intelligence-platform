# AppSec Intelligence Platform

A real-time application security platform that detects vulnerable dependencies the moment a CVE is published — not the next time a nightly scanner runs.

The platform streams CVEs from NVD and OSV, joins them against a live service dependency graph maintained by Apache Flink (PyFlink), and triggers an AI triage agent that fetches the affected source code, confirms exploitability, and generates a remediation report. Results are exposed via an MCP server queryable from VS Code in natural language.

**Detection lag: hours to days (batch scanning) → under 30 minutes (this platform).**

---

## Table of Contents

- [Architecture](#architecture)
- [Stack](#stack)
- [Quick Start](#quick-start)
- [Running with Docker](#running-with-docker)
- [Iterating Locally](#iterating-locally)
- [Data Sources](#data-sources)
- [Module Guide](#module-guide)
- [Demo Scenarios](#demo-scenarios)
- [Switching to Production](#switching-to-production)
- [Observability](#observability)
- [Project Structure](#project-structure)
- [PyFlink API Notes](#pyflink-api-notes)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              INGESTION LAYER  (Go)                       │
│  NVD Poller · OSV Poller · GitHub Events Poller         │
│  Archive Replayer · Synthetic Generator                  │
└──────────────────────┬──────────────────────────────────┘
                       │ Kafka (Redpanda)
┌──────────────────────▼──────────────────────────────────┐
│           STREAM PROCESSING LAYER  (PyFlink)             │
│  Normalise → Deduplicate → Dependency Graph              │
│  → CVE Join (Broadcast) → Blast Radius Score → Route    │
└──────────────────────┬──────────────────────────────────┘
                       │ Kafka
┌──────────────────────▼──────────────────────────────────┐
│              AI AGENT LAYER  (LangGraph)                 │
│  Triage Agent · PR Risk Agent · Posture Agent            │
│  Local: Ollama qwen2.5-coder:7b                          │
│  Production: Anthropic Claude Sonnet                     │
└────────┬──────────────────────────┬─────────────────────┘
         │                          │
┌────────▼───────┐        ┌─────────▼──────────────────────┐
│   MCP Server   │        │  Storage                        │
│  (9 tools)     │        │  PostgreSQL · MinIO · Qdrant    │
└────────┬───────┘        └────────────────────────────────┘
         │
┌────────▼─────────────────────────────────────────────────┐
│  VS Code + Cline · Slack Bot · Grafana · GitHub PR Gate  │
└──────────────────────────────────────────────────────────┘
```

---

## Stack

| Layer | Technology |
|---|---|
| Ingestion | Go 1.22 |
| Message bus | Redpanda (Kafka-compatible) |
| Stream processing | PyFlink 2.0 (DataStream API) |
| AI agents | LangGraph + Ollama / Claude Sonnet |
| Vector database | Qdrant |
| MCP server | Python MCP SDK |
| MCP client | VS Code + Cline extension |
| Object storage | MinIO (local) → AWS S3 (production) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Observability | Prometheus + Grafana |
| Infrastructure | Docker Compose |

Everything runs locally. No cloud accounts required in the default configuration.

---

## Quick Start

**Prerequisites:** Docker and `make` — that's it. All services run in containers.

```bash
# 1. Clone and configure
git clone https://github.com/yourusername/appsec-intelligence
cd appsec-intelligence
cp .env.example .env
# Edit .env — add GITHUB_TOKEN and NVD_API_KEY (both free, both optional)

# 2. Build all Docker images
make build

# 3. Start everything
make up
```

On first run Docker will build all images, Ollama will download the LLM models (~5 GB), and the database schema will be applied automatically. This takes a few minutes.

Once running, open Grafana at [http://localhost:3000](http://localhost:3000) to watch the pipeline.

Fire a demo scenario to see end-to-end detection:

```bash
make scenario SCENARIO=critical_rce
```

---

## Running with Docker

Everything is containerized. You do not need Go, Python, or any language runtime installed locally.

```bash
make build          # Build all images (do this once, or after code changes)
make up             # Start the full stack
make down           # Stop all containers (data is preserved)
make clean          # Stop and delete all volumes (full reset)
make ps             # Show running containers
make logs           # Tail all logs
make logs s=triage-agent   # Tail one service
```

**Layered startup** — bring up one layer at a time to understand what each piece does:

```bash
make infra-up       # Kafka, Postgres, MinIO, Qdrant, Redis, Prometheus, Grafana
make pollers-up     # Add the Go ingestion pollers + synthetic generator
make flink-up       # Add Flink and submit the stream processing topology
make agents-up      # Add Ollama model pull, triage agent, MCP server
```

**Rebuild a single service** after editing its code:

```bash
make rebuild s=triage-agent
make rebuild s=nvd-poller
```

**Open a shell inside a running container:**

```bash
make shell s=triage-agent
```

See [`infrastructure/README.md`](infrastructure/README.md) and [`infrastructure/flink/README.md`](infrastructure/flink/README.md) for details on the Docker Compose setup and Flink image.

---

## Iterating Locally

You do not need to run the full stack to work on a single component. Each layer can be started and tested in isolation.

| What you're building | Minimum services needed |
|---|---|
| Go ingestion pollers | Redpanda + Redis |
| PyFlink operators | Redpanda + PostgreSQL |
| Triage agent | Ollama + Qdrant + PostgreSQL |
| MCP server | PostgreSQL only |
| Synthetic generator | Redpanda + PostgreSQL |

To publish a test event directly to Kafka without running the full pipeline, use the Redpanda console at [http://localhost:8080](http://localhost:8080) or `rpk topic produce vuln.matches.critical`.

---

## Data Sources

Each ingestion source produces a different event type. Below is the raw API format from each source alongside the normalised event that gets published to Kafka.

### NVD — National Vulnerability Database

Polled every 5 minutes. The authoritative source for CVSS scores and CWE classification. Does **not** provide package-level version ranges — that comes from OSV.

**Raw API response (abbreviated):**
```json
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2024-35195",
      "published": "2024-05-20T09:15:00.000",
      "descriptions": [{
        "lang": "en",
        "value": "Requests is a HTTP library. Prior to 2.32.0, when making requests to HTTPS URLs, the SSL certificate is not verified..."
      }],
      "metrics": {
        "cvssMetricV31": [{
          "cvssData": {
            "baseScore": 5.9,
            "baseSeverity": "MEDIUM",
            "attackVector": "NETWORK",
            "attackComplexity": "HIGH"
          }
        }]
      },
      "weaknesses": [{"description": [{"value": "CWE-295"}]}]
    }
  }]
}
```

**Normalised `VulnerabilityEvent` published to `vulns.nvd.raw`:**
```json
{
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "cve_id": "CVE-2024-35195",
  "source": "nvd",
  "published_at": "2024-05-20T09:15:00Z",
  "ingested_at": "2024-05-20T09:17:43Z",
  "cvss_score": 5.9,
  "severity_tier": "MEDIUM",
  "cwe_id": "CWE-295",
  "description": "Requests is a HTTP library. Prior to 2.32.0...",
  "affected_package": "",
  "ecosystem": "",
  "affected_version_range": "",
  "affected_versions": []
}
```

> `affected_package` and `ecosystem` are intentionally empty for NVD events. NVD uses CPE strings which cannot be directly joined against package names. The Flink CVE join uses OSV events for version matching — NVD contributes CVSS scores and CWE IDs only.

---

### OSV.dev — Open Source Vulnerability Database

Bulk loaded from Google Cloud Storage on first run (~minutes per ecosystem), then polled incrementally every 10 minutes. Provides exact package names and version lists — this is what the Flink CVE join operator uses.

**Raw OSV API response:**
```json
{
  "vulns": [{
    "id": "GHSA-9wx4-h78v-vm56",
    "aliases": ["CVE-2024-35195"],
    "summary": "Requests has a .netrc credential leak",
    "modified": "2024-05-21T00:00:00Z",
    "affected": [{
      "package": {
        "name": "requests",
        "ecosystem": "PyPI"
      },
      "ranges": [{
        "type": "ECOSYSTEM",
        "events": [
          {"introduced": "0"},
          {"fixed": "2.32.0"}
        ]
      }],
      "versions": ["2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.30.0", "2.31.0"]
    }]
  }]
}
```

**Normalised `VulnerabilityEvent` published to `vulns.osv.raw`:**
```json
{
  "event_id": "f7e8d9c0-b1a2-3456-cdef-789012345678",
  "cve_id": "CVE-2024-35195",
  "source": "osv",
  "published_at": "2024-05-20T09:15:00Z",
  "ingested_at": "2024-05-20T09:20:11Z",
  "cvss_score": 0.0,
  "severity_tier": "MEDIUM",
  "description": "Requests has a .netrc credential leak",
  "affected_package": "requests",
  "ecosystem": "pypi",
  "affected_version_range": "< 2.32.0",
  "safe_version": "2.32.0",
  "affected_versions": ["2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.30.0", "2.31.0"]
}
```

> `cvss_score` is 0.0 — OSV does not always include CVSS data. The Flink deduplicator merges NVD and OSV events for the same CVE ID so the final match event carries OSV's version range alongside NVD's CVSS score.

---

### GitHub Events API

Polled every 60 seconds across 15 target repositories. Captures real Dependabot and Renovate PR merges as they happen. Uses repo name directly as `service_id`.

**Raw GitHub Events API response:**
```json
{
  "type": "PullRequestEvent",
  "actor": {"login": "dependabot[bot]"},
  "repo": {"name": "psf/requests"},
  "payload": {
    "action": "closed",
    "pull_request": {
      "number": 6782,
      "title": "Bump urllib3 from 1.26.14 to 2.0.7",
      "merged": true,
      "merged_at": "2024-02-15T11:45:22Z",
      "head": {"ref": "dependabot/pip/urllib3-2.0.7"}
    }
  },
  "created_at": "2024-02-15T11:45:23Z"
}
```

**Normalised `DependencyChangeEvent` published to `deps.changes`:**
```json
{
  "event_id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
  "source": "github_events_api",
  "repo": "psf/requests",
  "service_id": "psf/requests",
  "pr_number": 6782,
  "author": "dependabot[bot]",
  "ecosystem": "pypi",
  "manifest_file": "requirements.txt",
  "added": [],
  "removed": [],
  "updated": [{
    "package": "urllib3",
    "from_version": "1.26.14",
    "to_version": "2.0.7"
  }],
  "occurred_at": "2024-02-15T11:45:22Z",
  "ingested_at": "2024-02-15T11:45:31Z"
}
```

---

### GitHub Archive

Hourly `.json.gz` files from [gharchive.org](https://gharchive.org). Each file contains 3–5 million events covering all public GitHub activity for that hour. The replayer filters this down to merged Dependabot PRs from 2024 onwards — roughly 5,000–15,000 usable events per hour of archive data.

**Raw archive line (NDJSON — one JSON object per line):**
```json
{"type":"PullRequestEvent","actor":{"login":"dependabot[bot]"},"repo":{"name":"django/django"},"payload":{"action":"closed","pull_request":{"number":17291,"title":"Bump pillow from 9.5.0 to 10.3.0","merged":true,"merged_at":"2024-03-14T08:22:01Z","head":{"ref":"dependabot/pip/pillow-10.3.0"}}},"created_at":"2024-03-14T08:22:02Z"}
```

> The archive uses the same event format as the Events API. The replayer applies identical parsing logic — the only difference is `source` is set to `gh_archive` and events are read from bulk files rather than a REST endpoint. Pre-2024 events are rejected because Dependabot adoption was inconsistent and package versions don't align with current CVEs.

---

### Synthetic Generator

Produces two types of events: a continuous background hum of realistic dependency bumps at ~2 events/second, and named demo scenarios that inject specific vulnerable packages into specific services on demand.

**Background hum event:**
```json
{
  "event_id": "99887766-5544-3322-1100-aabbccddeeff",
  "source": "synthetic",
  "repo": "checkout-api",
  "service_id": "checkout-api",
  "pr_number": 4821,
  "author": "dependabot[bot]",
  "ecosystem": "pypi",
  "manifest_file": "requirements.txt",
  "added": [],
  "removed": [],
  "updated": [{"package": "requests", "from_version": "2.28.0", "to_version": "2.31.0"}],
  "occurred_at": "2024-01-15T14:30:00Z",
  "ingested_at": "2024-01-15T14:30:00Z"
}
```

**`critical_rce` scenario event (pins a known-vulnerable version to trigger the full pipeline):**
```json
{
  "event_id": "11223344-5566-7788-99aa-bbccddeeff00",
  "source": "synthetic",
  "repo": "checkout-api",
  "service_id": "checkout-api",
  "pr_number": 9900,
  "author": "dependabot[bot]",
  "ecosystem": "pypi",
  "manifest_file": "requirements.txt",
  "added": [{"package": "requests", "version": "2.28.0"}],
  "removed": [],
  "updated": [],
  "occurred_at": "2024-01-15T14:30:00Z",
  "ingested_at": "2024-01-15T14:30:00Z"
}
```

---

## Module Guide

Each module has its own README with implementation details, configuration options, and how to run it in isolation.

| Module | README | Description |
|---|---|---|
| `ingestion/` | [`ingestion/README.md`](ingestion/README.md) | Go pollers for NVD, OSV, and GitHub — publish raw CVE and dependency change events to Kafka |
| `stream-processing/` | [`stream-processing/README.md`](stream-processing/README.md) | PyFlink topology — normalise, deduplicate, join CVEs to dependency graph, score, and route |
| `agents/` | [`agents/README.md`](agents/README.md) | LangGraph AI agents — triage, PR risk assessment, daily posture report |
| `mcp-server/` | [`mcp-server/README.md`](mcp-server/README.md) | MCP server exposing 9 query tools to AI assistants (VS Code, Claude Desktop) |
| `shared/` | [`shared/README.md`](shared/README.md) | Shared Python package — Pydantic schemas, config, structured logging |
| `scripts/synthetic-generator/` | [`scripts/synthetic-generator/README.md`](scripts/synthetic-generator/README.md) | Demo data generator — background hum and on-demand scenarios |
| `scripts/corpus-builder/` | [`scripts/corpus-builder/README.md`](scripts/corpus-builder/README.md) | One-time job that indexes OSV data into Qdrant for RAG retrieval |
| `infrastructure/` | [`infrastructure/README.md`](infrastructure/README.md) | Docker Compose stack — all services, volumes, and networking |
| `infrastructure/flink/` | [`infrastructure/flink/README.md`](infrastructure/flink/README.md) | Custom Flink Docker image — Kafka connector JAR, MinIO plugin, Python deps |

---

### Ingestion Layer — `ingestion/`

Four independent Go binaries that poll upstream sources and publish normalised events to Kafka. Stateless except for Redis-backed cursors that track polling position. All share a common Kafka producer and event schema via `ingestion/shared/`.

| Module | What it does |
|---|---|
| `nvd-poller` | Polls the NVD REST API every 5 minutes using a Redis cursor to track the last seen publication date. Normalises CVE records to `VulnerabilityEvent` and publishes to `vulns.nvd.raw`. Provides CVSS scores and CWE IDs. A free API key increases the rate limit from 5 to 50 requests per 30 seconds. |
| `osv-poller` | On first run, bulk loads the full OSV corpus from Google Cloud Storage (one `.zip` per ecosystem). Then polls incrementally every 10 minutes. Provides exact package names and affected version lists — the primary source for the Flink CVE join. Publishes to `vulns.osv.raw`. No authentication required. |
| `github-events-poller` | Polls 15 high-activity open source repos every 60 seconds. Filters for merged Dependabot and Renovate PRs, extracts package and version from the branch name and PR title, and publishes `DependencyChangeEvent` records to `deps.changes`. |
| `archive-replayer` | Downloads hourly `.json.gz` files from [gharchive.org](https://gharchive.org) and replays merged Dependabot PRs from 2024 onwards. Three modes: `seed` (run once to populate the Flink dep graph), `loadtest` (max speed), `continuous` (steady replay loop). |
| `shared/kafka` | Shared `NewProducer()` with idempotent delivery, snappy compression, and async delivery failure logging. |
| `shared/schemas` | Canonical Go structs for `VulnerabilityEvent` and `DependencyChangeEvent` with helper functions. |

→ Full details: [`ingestion/README.md`](ingestion/README.md)

---

### Stream Processing Layer — `stream-processing/`

A single PyFlink job (`topology.py`) composed of six operators. Uses the DataStream API with RocksDB state backend for keyed state and exactly-once checkpointing to MinIO every 60 seconds.

| Operator | Flink API | What it does |
|---|---|---|
| `normaliser.py` | `FlatMapFunction` | Validates and normalises raw CVE JSON. Drops malformed records silently. |
| `deduplicator.py` | `KeyedProcessFunction` + `ValueState` | Drops duplicate CVEs (same CVE is routinely published by both NVD and OSV) using 24-hour TTL state. |
| `dependency_graph.py` | `KeyedProcessFunction` + `MapState` (RocksDB) | Maintains a live `{package → version}` map per service. Applies deltas from each dependency change event. |
| `cve_join.py` | `BroadcastProcessFunction` | Broadcasts the CVE stream to all task instances so each can check dep graph snapshots against all recent CVEs. |
| `blast_radius_scorer.py` | `MapFunction` | Composite risk score: CVSS 40% + customer-facing 25% + compliance scope 20% + PII 15%. Sets SLA deadline. |
| `router.py` | `FlatMapFunction` | Routes scored matches to severity-tiered Kafka topics. |

→ Full details: [`stream-processing/README.md`](stream-processing/README.md)

---

### AI Agent Layer — `agents/`

Three LangGraph agents. The LLM is called only in final synthesis steps — all evidence gathering is deterministic tool calls. This keeps a 7B local model viable.

| Module | What it does |
|---|---|
| `llm_provider.py` | Single switch between Ollama (local) and Anthropic Claude (production) via `LLM_PROVIDER` env var. |
| `triage/agent.py` | 5-node graph: RAG retrieval → GitHub code fetch → LLM exploitability check → OSV remediation lookup → LLM synthesis into `TriageReport`. Short-circuits if not affected. |
| `triage/consumer.py` | Kafka consumer on `vuln.matches.critical` and `vuln.matches.high`. Writes reports to PostgreSQL. |
| `pr_risk/agent.py` | Assesses PRs adding new dependencies. Posts APPROVE / WARN / BLOCK verdict as a GitHub PR review. |
| `posture/agent.py` | Daily posture report — open counts, SLA breach rates, compliance gaps, executive summary. |
| `rag/retriever.py` | Qdrant semantic search across collections. |
| `tools/` | GitHub code search, OSV safe version lookup, deps.dev transitive dep resolution, service registry lookup. |

→ Full details: [`agents/README.md`](agents/README.md)

---

### MCP Server — `mcp-server/`

A thin query layer exposing 9 tools over the Model Context Protocol. Translates natural language tool calls into PostgreSQL queries and Qdrant searches.

| Tool | Returns |
|---|---|
| `get_vulnerability_exposure` | Open vulnerabilities for a service with blast radius tier and SLA deadline |
| `get_cve_details` | Full triage report — exploitability verdict, code locations, remediation command |
| `search_vulnerabilities` | Semantic search over triaged reports |
| `get_remediation_path` | Safe upgrade path with compatibility notes |
| `get_affected_services` | All services affected by a CVE with blast radius scores |
| `get_team_exposure` | All open vulnerabilities for a team, sorted by SLA urgency |
| `get_compliance_gaps` | Vulnerabilities mapped to PCI DSS / SOC 2 / HIPAA / ISO 27001 controls |
| `get_security_posture_summary` | Most recent daily posture report with trend analysis |
| `get_dependency_graph` | Live dependency snapshot for a service from Flink state |

→ Full details: [`mcp-server/README.md`](mcp-server/README.md)

---

### Shared Python Package — `shared/`

An installable package (`pip install -e ./shared`) shared across stream-processing, agents, and the MCP server.

| Module | What it provides |
|---|---|
| `appsec_shared/schemas/` | Pydantic v2 models for all event and report types. Validates on construction. |
| `appsec_shared/config/` | `pydantic-settings` `Settings` class. Reads from environment and `.env`. Fails fast on missing required vars. |
| `appsec_shared/logging.py` | `structlog` JSON logging. Call `configure_logging("service-name")` once at startup. |

→ Full details: [`shared/README.md`](shared/README.md)

---

### Synthetic Generator — `scripts/synthetic-generator/`

A standalone container providing controlled demo data — a 2 events/sec background hum and on-demand scenarios triggered via HTTP.

→ Full details: [`scripts/synthetic-generator/README.md`](scripts/synthetic-generator/README.md)  
→ Corpus builder: [`scripts/corpus-builder/README.md`](scripts/corpus-builder/README.md)

---

### Infrastructure — `infrastructure/`

→ Docker Compose setup: [`infrastructure/README.md`](infrastructure/README.md)  
→ Flink Docker image: [`infrastructure/flink/README.md`](infrastructure/flink/README.md)

---


## Demo Scenarios

| Scenario | What fires | Expected pipeline output |
|---|---|---|
| `critical_rce` | `requests==2.28.0` in 3 PCI-scoped services | CRITICAL triage reports, Slack alerts to payments team |
| `mass_exposure` | `cryptography==41.0.0` in 8 services across 4 teams | Blast radius scoring and team-level routing |
| `supply_chain_attack` | `PyYAML==5.3.1` added in a PR | PR Risk Agent posts BLOCK verdict |
| `log4shell_redux` | Log4j 1.2.17 + Spring4Shell in legacy Java service | Maven ecosystem, multi-CVE detection |
| `safe_upgrade_wave` | 10 services upgrade to `requests==2.32.1` | No alerts — validates non-firing |
| `pr_risk_safe` | `httpx==0.27.0` added to checkout-api | PR Risk Agent posts APPROVE verdict |

---

## Switching to Production

Configuration-only — no code changes required.

```bash
# LLM: Ollama → Claude
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...         # embeddings only

# Storage: MinIO → AWS S3
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
# Remove: AWS_ENDPOINT_URL and S3_FORCE_PATH_STYLE
```

---

## Observability

| URL | Service | Credentials |
|---|---|---|
| http://localhost:3000 | Grafana | admin / admin |
| http://localhost:8081 | Flink job manager UI | — |
| http://localhost:9001 | MinIO console | minioadmin / minioadmin |
| http://localhost:8080 | Redpanda console | — |
| http://localhost:8090 | Scenario trigger UI | — |
| http://localhost:9090 | Prometheus | — |

---

## Project Structure

```
appsec-intelligence/
│
├── ingestion/                              # Go — all ingestion services (single module)
│   ├── go.mod
│   ├── nvd-poller/
│   │   └── main.go                         # Polls NVD every 5 min → vulns.nvd.raw
│   ├── osv-poller/
│   │   └── main.go                         # Bulk loads OSV, polls every 10 min → vulns.osv.raw
│   ├── github-events-poller/
│   │   └── main.go                         # Polls 15 repos every 60s → deps.changes
│   ├── archive-replayer/
│   │   └── main.go                         # gharchive.org replay: seed | loadtest | continuous
│   └── shared/
│       ├── kafka/producer.go               # Shared idempotent Kafka producer
│       └── schemas/events.go               # VulnerabilityEvent + DependencyChangeEvent structs
│
├── stream-processing/                      # Python — PyFlink DataStream topology
│   ├── topology.py                         # Job definition: sources, operator chain, sinks
│   ├── requirements.txt                    # apache-flink==2.0.0, psycopg2, packaging
│   ├── operators/
│   │   ├── normaliser.py                   # FlatMapFunction — validate + normalise CVE JSON
│   │   ├── deduplicator.py                 # KeyedProcessFunction + ValueState (24h TTL)
│   │   ├── dependency_graph.py             # KeyedProcessFunction + MapState (RocksDB)
│   │   ├── cve_join.py                     # BroadcastProcessFunction — CVE × dep graph join
│   │   ├── blast_radius_scorer.py          # MapFunction — composite weighted risk score
│   │   └── router.py                       # FlatMapFunction — route to severity-tiered topics
│   └── tests/
│       └── test_operators.py               # Unit tests (no Flink cluster required)
│
├── agents/                                 # Python — LangGraph AI agents
│   ├── llm_provider.py                     # Single switch: LLM_PROVIDER=ollama|anthropic
│   ├── requirements.txt
│   ├── triage/
│   │   ├── agent.py                        # 5-node LangGraph graph (LLM only in nodes 3 + 5)
│   │   └── consumer.py                     # Kafka consumer — vuln.matches.critical + .high
│   ├── pr_risk/
│   │   └── agent.py                        # PR dependency risk assessment → GitHub PR comment
│   ├── posture/
│   │   └── agent.py                        # Daily posture report (cron 06:00 UTC)
│   ├── rag/
│   │   └── retriever.py                    # Qdrant semantic search across collections
│   └── tools/
│       ├── github.py                       # GitHub code search + file fetch
│       ├── osv.py                          # OSV.dev safe version lookup
│       ├── deps_dev.py                     # deps.dev transitive dependency resolution
│       └── service_registry.py             # PostgreSQL service metadata lookup
│
├── mcp-server/                             # Python — MCP server (9 tools)
│   ├── server.py                           # Tool definitions + stdio transport
│   └── tools/
│       ├── vulnerability.py                # get_vulnerability_exposure, get_cve_details, get_affected_services
│       ├── search.py                       # search_vulnerabilities (Qdrant)
│       ├── remediation.py                  # get_remediation_path
│       ├── compliance.py                   # get_compliance_gaps
│       └── posture.py                      # get_team_exposure, get_security_posture_summary, get_dependency_graph
│
├── shared/                                 # Python — shared installable package
│   ├── pyproject.toml                      # pip install -e ./shared
│   └── appsec_shared/
│       ├── schemas/__init__.py             # Pydantic v2 event + report models
│       ├── config/__init__.py              # pydantic-settings Settings class
│       └── logging.py                      # structlog JSON logging setup
│
├── scripts/
│   ├── synthetic-generator/                # Python — demo data container
│   │   ├── Dockerfile
│   │   ├── main.py                         # HTTP server (:8090) + background hum
│   │   ├── registry.py                     # 50 synthetic services with compliance metadata
│   │   ├── scenarios.py                    # 6 named demo scenarios
│   │   └── requirements.txt
│   └── corpus-builder/
│       └── build_corpus.py                 # Index OSV + GitHub data into Qdrant
│
├── infrastructure/
│   ├── docker-compose.yml                  # 12-service local stack, all images pinned
│   ├── sql/
│   │   └── schema.sql                      # PostgreSQL schema (auto-applied on first start)
│   └── grafana/
│       └── dashboards/                     # Pipeline health + security intelligence dashboards
│
├── docs/
│   └── PRD.md                              # Full product requirements document (v2.0)
│
├── .env.example                            # All environment variables with comments
├── .gitignore
├── Makefile                                # Developer workflow — run `make help`
└── README.md
```

---

## PyFlink API Notes

This project uses the PyFlink **DataStream API** only. Key constraints respected throughout:

- `BroadcastProcessFunction` — used for the CVE × dependency graph join. Available in the Python API since Flink 1.16.
- `KeyedProcessFunction` + `MapState` — used for the dependency graph operator. RocksDB-backed, survives restarts via MinIO checkpoints.
- `StateTtlConfig` — used in the deduplicator for automatic 24-hour state expiry. Available in the Python API.
- **CEP is not used** — Complex Event Processing is Java-only and not available in the Python API.
- Broadcast state is always heap-based — RocksDB cannot back it. This is fine: only the small CVE stream is broadcast, not the large dependency graph.

---

## License

MIT
