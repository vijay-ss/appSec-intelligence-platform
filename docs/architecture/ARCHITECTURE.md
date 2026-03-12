# Architecture — AppSec Intelligence Platform

## The core problem

Traditional vulnerability scanners run on a schedule — nightly, weekly, or on every CI build. This means there's always a window between when a CVE is published and when your team finds out they're affected. That window is typically 12–72 hours.

This platform eliminates that window by treating vulnerability detection as a streaming problem: CVEs and dependency changes are both streams of events, and the question "is my service affected?" can be answered continuously as both streams update.

---

## Data flow

```
NVD API ──────────────────────-┐
                               ├──► Kafka: vulns.nvd.raw ──-┐
OSV.dev API ──────────────────-┘                            │
                                                            ▼
                                                  ┌─── Normaliser ──────────────────-┐
GitHub Events API ─────────────────────────────── │                                  │
                               ┌──► deps.changes  │   Deduplicator                   │
GitHub Archive ────────────────┘                  │       │                          │
                                                  │       ▼                          │
Synthetic Generator ──────────────────────────────┘   Dep Graph (RocksDB) ──────►    │
                                                           │ snapshots               │
                                                           └──────────────► CVE Join ┘
                                                                                │
                                                                    Blast Radius Scorer
                                                                                │
                                                                            Router
                                                                                │
                                        ┌───────────────────────────────────────┤
                                        ▼                       ▼               ▼
                               vuln.matches.critical    vuln.matches.high   deps.risk.prs
                                        │                       │               │
                                        ▼                       ▼               ▼
                                  Triage Agent            Triage Agent    PR Risk Agent
                                        │                       │               │
                                        └───────────┬───────────┘               │
                                                    ▼                           ▼
                                               PostgreSQL                  GitHub PR
                                               triage_reports              review comment
                                                    │
                                                    ▼
                                               MCP Server
                                                    │
                                                    ▼
                                            VS Code / Cline
```

---

## Layer responsibilities

### Ingestion (Go)

Stateless pollers. Each one knows how to talk to one upstream API, normalise its response to a canonical schema, and publish to a Kafka topic. They don't know anything about each other or about Flink.

State is limited to a Redis cursor — the last-seen timestamp or page — so a restarted poller picks up exactly where it left off.

**Why Go?** The pollers are I/O-bound and need to be reliable over long periods. Go's concurrency model, low memory footprint, and simple deployment (single binary) make it well-suited.

### Stream Processing (PyFlink)

One job, six operators in a chain. The job's only purpose is to answer: "does this service's current dependency state contain a package affected by any known CVE?"

The hard part is that both sides of this join are streams — CVEs arrive continuously, and dependency states change continuously. You can't do a one-time join; you need to maintain state on both sides and re-evaluate whenever either changes.

Flink's stateful stream processing handles this cleanly:
- **Keyed state** (RocksDB) — the dependency graph, keyed by service_id. Large, long-lived, disk-backed.
- **Broadcast state** (heap) — the recent CVE window, broadcast to all parallel task instances. Small (~200 CVEs/day), short-lived (24h TTL).

Every time a service's dependency state changes, a snapshot is emitted and checked against all recent CVEs. Every time a new CVE arrives, it's broadcast to all instances so they can check it against their local dependency graph state.

**Why PyFlink and not Spark/Beam/Kafka Streams?** PyFlink's Python DataStream API is the only framework that gives you true stateful stream processing (not micro-batch), RocksDB-backed keyed state, exactly-once guarantees, and a Python API that doesn't require Java interop. Kafka Streams is Java-only. Spark Streaming is micro-batch. Beam has a Python API but less operator-level control.

### AI Agent Layer (LangGraph)

Three agents that add intelligence on top of raw match data. The design principle is **evidence first, LLM last**: agents run several deterministic tool calls to gather facts (source code, CVE details, version ranges, service metadata), then hand everything to the LLM to synthesise.

This approach works well with smaller local models (7B parameters) because the LLM only needs to reason over what's explicitly in the prompt — it doesn't need encyclopedic knowledge of specific CVEs or codebases.

LangGraph is used rather than a simple function chain because the triage agent has a conditional edge: if the LLM's exploitability assessment returns NOT_AFFECTED, the graph short-circuits and skips report generation entirely. This prevents false positives from generating noise.

### MCP Server (Python)

A thin translation layer between the Model Context Protocol and the database. No reasoning happens here — just SQL queries and Qdrant searches. The value is that any MCP-compatible AI assistant (VS Code + Cline, Claude Desktop, etc.) can query the platform's output in natural language without any integration work.

---

## State management

The platform has three distinct kinds of state:

| State | Where | Backed by | TTL / Retention |
|---|---|---|---|
| NVD polling cursor | Redis | In-memory | Forever (reset to re-poll) |
| OSV bulk load flag | Redis | In-memory | Forever |
| Dep graph (per service) | Flink RocksDB | Disk + MinIO checkpoints | Forever (append-only) |
| CVE broadcast window | Flink heap | Memory | 24 hours (StateTtlConfig) |
| Dedup seen-keys | Flink RocksDB | Disk + MinIO checkpoints | 24 hours (StateTtlConfig) |
| Vulnerability records | PostgreSQL | Disk | Forever |
| Triage reports | PostgreSQL + MinIO | Disk | Forever |
| Posture reports | PostgreSQL + MinIO | Disk | Forever |
| Vector embeddings | Qdrant | Disk | Forever (re-indexed by corpus builder) |

---

## Failure modes

### A Flink task crashes mid-stream

Flink restarts the task and replays from the last checkpoint (written every 60 seconds to MinIO). Because checkpointing uses exactly-once semantics with the Kafka connector, no events are lost and none are double-processed. The dep graph state is fully restored from the checkpoint.

### A Go poller crashes

The Redis cursor is updated only after successful Kafka publish. On restart, the poller reads the cursor and resumes from where it left off. At most one poll interval of events could be missed (5 minutes for NVD, 10 minutes for OSV).

### An agent crashes mid-report

The Kafka offset is committed only after the triage report is written to PostgreSQL. If the agent crashes before writing, the message is re-delivered on restart and the report is generated again. The `ON CONFLICT DO UPDATE` in the SQL insert handles duplicate report_ids safely.

### PostgreSQL is temporarily unavailable

The blast radius scorer's in-process cache means Flink operators continue processing (using cached metadata) for a short period. The triage agent will fail and leave the Kafka message uncommitted — it will be retried on restart.

---

## Scaling to production

The platform is designed so production deployment is a configuration change, not an architectural change.

| Component | Local | Production |
|---|---|---|
| Message bus | Redpanda (single node) | Redpanda Cloud or MSK |
| Flink | Docker Compose (2 task slots) | Flink on K8s or AWS KDA |
| State backend | RocksDB + MinIO | RocksDB + S3 |
| Database | PostgreSQL 16 | RDS PostgreSQL |
| Vector DB | Qdrant (single node) | Qdrant Cloud |
| LLM | Ollama qwen2.5-coder:7b | Anthropic Claude Sonnet |
| Embeddings | nomic-embed-text (Ollama) | OpenAI text-embedding-3-large |

The single code change required for production: `LLM_PROVIDER=anthropic` in the environment.
