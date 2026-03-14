# Infrastructure

Local development stack defined in Docker Compose. All services run on a single machine. No cloud accounts, no Kubernetes, no Terraform.

---

## Starting the stack

```bash
# From the repo root — build all images (first time or after code changes)
make build

# Start everything
make up

# Or bring up one layer at a time
make infra-up       # infrastructure only (Kafka, Postgres, MinIO, etc.)
make pollers-up     # add Go ingestion pollers
make flink-up       # add Flink + submit the topology
make agents-up      # add Ollama + triage agent + MCP server
```

### Useful commands

```bash
make ps             # show all containers and their health status
make logs           # tail all logs
make logs s=postgres  # tail one service
make down           # stop everything (data is preserved in volumes)
make clean          # stop everything and delete all volumes (full reset)
```

### Minimal subset (when working on a specific layer)

You don't need the full stack running to work on a single component:

| Working on | Start these |
|---|---|
| Go ingestion pollers | `make infra-up` (just Redpanda + Redis) |
| PyFlink operators (unit tests) | nothing — `make test` runs in a container with no cluster |
| Triage agent | `make infra-up` + Ollama + `docker compose up -d postgres qdrant` |
| MCP server | `docker compose up -d postgres qdrant redis` |

---

## Services

### Redpanda (Kafka-compatible message bus)

Replaces Apache Kafka. Redpanda is a single binary — no ZooKeeper, no JVM, significantly lower memory footprint. The Kafka protocol is fully compatible so all Kafka client libraries (`confluent-kafka-go`, `confluent-kafka-python`, PyFlink's Kafka connector) work without modification.

**Port:** `9092` (Kafka protocol), `8080` (Redpanda console UI)

The console at [http://localhost:8080](http://localhost:8080) lets you inspect topic messages, consumer group lag, and partition offsets without any additional tooling. This is the fastest way to verify that ingestion pollers are producing correctly formatted events.

**Topics created automatically by producers on first message:**
- `vulns.nvd.raw` — normalised NVD CVE events
- `vulns.osv.raw` — normalised OSV vulnerability events
- `deps.changes` — dependency change events from all sources
- `vuln.matches.critical` — CRITICAL blast radius matches
- `vuln.matches.high` — HIGH blast radius matches
- `vuln.matches.medium` — MEDIUM blast radius matches
- `vuln.matches.low` — LOW blast radius matches
- `deps.risk.prs` — dependency addition events for PR risk assessment
- `vuln.graph.snapshots` — live dep graph state snapshots

---

### MinIO (S3-compatible object storage)

Used for two things: Flink checkpoint storage (required for exactly-once guarantees and job recovery) and posture report archival. Locally it's a single-container MinIO instance. In production, replace with AWS S3 by removing the `AWS_ENDPOINT_URL` environment variable.

**Ports:** `9000` (S3 API), `9001` (MinIO console UI)
**Credentials:** `minioadmin` / `minioadmin`

The `minio-init` container runs once on startup and creates the required buckets:
- `flink-checkpoints` — Flink job state checkpoints (written every 60 seconds)
- `appsec-audit-log` — audit trail of all pipeline events
- `appsec-rag-corpus` — raw documents before Qdrant indexing
- `appsec-backups` — posture report JSON archives

---

### Apache Flink (stream processing cluster)

Two containers: a job manager (coordinates the job, manages checkpoints) and a task manager (executes operators). The task manager has 4 task slots, allowing up to 4 parallel operator instances for each job stage.

**Port:** `8081` (Flink job manager UI)

The job manager UI shows:
- Running jobs and their operator DAGs
- Per-operator throughput and latency
- Checkpoint history and sizes
- Task slot allocation

**Image:** `apache/flink:1.20-python3` — includes Python 3 support required for PyFlink.

The Flink configuration is passed via the `FLINK_PROPERTIES` environment variable. Key settings:
```
state.backend: rocksdb                   # RocksDB for large keyed state
state.checkpoints.dir: s3://...          # MinIO checkpoint storage
s3.endpoint: http://minio:9000           # MinIO S3 endpoint
s3.path.style.access: true              # Required for MinIO
```

---

### Qdrant (vector database)

Stores embedded documents for RAG retrieval. Three collections are created by the corpus builder and triage consumer:
- `cve_descriptions` — CVE text indexed from OSV and NVD
- `exploit_reports` — public exploit POC summaries
- `triage_reports` — past triage report text (enables semantic search via MCP)

**Port:** `6333`

Qdrant persists data to a Docker volume (`qdrant_data`). The corpus builder populates it on first run — see `scripts/corpus-builder/`.

---

### PostgreSQL 16

The primary persistence layer for all structured data. The schema is applied automatically when the container first starts via the `docker-entrypoint-initdb.d` mechanism — `infrastructure/sql/schema.sql` is mounted into that directory.

**Port:** `5432`
**Connection:** `postgresql://appsec:appsec@localhost:5432/appsec`

See `sql/schema.sql` for the full table definitions. Key tables:

| Table | Written by | Read by |
|---|---|---|
| `vulnerabilities` | NVD/OSV pollers (via Flink) | MCP server, agents |
| `vulnerability_matches` | Flink blast radius scorer | MCP server, agents, posture agent |
| `triage_reports` | Triage agent consumer | MCP server |
| `service_registry` | Synthetic generator (seed), manual | All layers |
| `dep_graph_snapshots` | Flink dep graph operator | MCP `get_dependency_graph` |
| `posture_reports` | Posture agent | MCP `get_security_posture_summary` |
| `audit_log` | All write operations | Compliance tooling |

---

### Redis 7

Used exclusively by the Go ingestion pollers for polling cursors. Two keys are used:
- `nvd:cursor:last_pub_date` — timestamp of the last NVD CVE processed
- `osv:bulk_loaded` — flag indicating the OSV bulk load has completed

**Port:** `6379`

Redis is also available for use by the agent layer for response caching if needed during development.

---

### Ollama

Runs the local LLM and embeddings models. Configured with a Docker volume (`ollama_data`) so models are downloaded once and persist across container restarts.

**Port:** `11434`

Models used:
- `qwen2.5-coder:7b-instruct-q4_K_M` — chat model for the agents (~4.5GB)
- `nomic-embed-text` — embeddings model for RAG (~270MB)

Pull models after first `make up`:
```bash
make models
```

On Apple Silicon, Ollama uses Metal GPU acceleration automatically. On Linux with an NVIDIA GPU, uncomment the `deploy` section in `docker-compose.yml`.

---

### Prometheus + Grafana

Standard observability stack.

**Ports:** Prometheus `9090`, Grafana `3000`
**Grafana credentials:** `admin` / `admin`

Two dashboards are provisioned automatically from `grafana/dashboards/`:

**Pipeline Health:** Flink job throughput per operator, Kafka consumer group lag per topic, checkpoint success/failure rate, MinIO write latency.

**Security Intelligence:** Open vulnerabilities by tier over time, MTTD and MTTR trends, SLA compliance rate by team, new CVE detection volume by ecosystem.

---

### Synthetic Generator

See `scripts/synthetic-generator/README.md` for full documentation.

**Ports:** `8090` (scenario HTTP server)

---

## Database schema — `sql/schema.sql`

Applied automatically on first PostgreSQL container start. Re-run manually after schema changes:

```bash
make migrate
```

All tables use `IF NOT EXISTS` so `make migrate` is safe to run multiple times. Foreign key constraints are enforced — `vulnerability_matches.cve_id` references `vulnerabilities.cve_id`, and `triage_reports.match_id` references `vulnerability_matches.match_id`.

Indexes are created on the most common query patterns:
- `vulnerability_matches(status)` — filter open findings
- `vulnerability_matches(service_id)` — per-service queries
- `vulnerability_matches(assigned_team)` — team exposure queries
- `vulnerability_matches(sla_deadline)` — SLA breach monitoring
- `dep_graph_snapshots(service_id, snapshot_at DESC)` — latest snapshot per service

---

## Resource usage

Approximate idle memory consumption on a MacBook Pro M2 Pro (16GB RAM):

| Service | Memory |
|---|---|
| Redpanda | ~300MB |
| MinIO | ~150MB |
| Flink job manager | ~400MB |
| Flink task manager | ~600MB |
| Qdrant | ~200MB |
| PostgreSQL | ~150MB |
| Redis | ~30MB |
| Ollama (model loaded) | ~5GB |
| Prometheus + Grafana | ~300MB |
| Synthetic generator | ~100MB |
| **Total** | **~7.2GB** |

This leaves ~8GB free on a 16GB machine for the Go ingestion services and Python agent processes.

If memory is tight, the Prometheus and Grafana containers can be omitted without affecting core pipeline functionality. Ollama can also be run natively on macOS (outside Docker) to use Metal GPU acceleration and reduce overall container overhead.
