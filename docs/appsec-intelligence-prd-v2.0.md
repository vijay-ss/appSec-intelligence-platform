# Real-Time AppSec Intelligence Platform
## Project Requirements Document

**Version:** 2.0.0
**Status:** Approved
**Last Updated:** 2026-03-06
**Classification:** Portfolio / Public

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-01 | Initial PRD |
| 1.1.0 | 2026-03-05 | MinIO replaces S3, Ollama replaces Claude as default, cybersecurity standards section added, downstream apps section added |
| 2.0.0 | 2026-03-06 | MCP client updated to VS Code + Cline, Ollama model recommendation updated for M2 Pro 16GB, Terraform removed from core scope, Kubernetes deferred to Phase 6, archive replayer operating modes defined, synthetic generator expanded, downstream applications expanded, data sources section rewritten with throughput analysis |

---

## How to Use This Document

This PRD is written to serve two purposes simultaneously:

1. **Human reading** — a complete project specification for contributors, recruiters, and collaborators reviewing the repository
2. **LLM prompting** — each section is self-contained and can be extracted as prompt context for code generation

Recommended LLM prompt patterns by section:

| Task | Feed These Sections |
|------|-------------------|
| Scaffold Go ingestion services | Section 5 + Section 15 |
| Generate PyFlink topology | Section 6 + Section 15 |
| Build LangGraph agent | Section 7 + Section 7.1 + Section 15 |
| Implement LLM provider abstraction | Section 7.1 |
| Scaffold MCP server | Section 8 |
| Generate PostgreSQL schema | Section 9.3 |
| Build Docker Compose stack | Section 11 |
| Write archive replayer | Section 4.5 + Section 5.4 |
| Write synthetic generator | Section 5.5 |
| Build downstream apps | Section 17 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Business Objective](#2-business-objective)
3. [System Overview](#3-system-overview)
4. [Data Sources and Throughput](#4-data-sources-and-throughput)
5. [Ingestion Layer — Go](#5-ingestion-layer--go)
6. [Stream Processing Layer — PyFlink](#6-stream-processing-layer--pyflink)
7. [AI Agent Layer](#7-ai-agent-layer)
8. [MCP Server](#8-mcp-server)
9. [Storage Layer](#9-storage-layer)
10. [Local Development Environment](#10-local-development-environment)
11. [Observability](#11-observability)
12. [Non-Functional Requirements](#12-non-functional-requirements)
13. [Repository Structure](#13-repository-structure)
14. [Development Phases](#14-development-phases)
15. [Event Schemas](#15-event-schemas)
16. [Cybersecurity Standards Alignment](#16-cybersecurity-standards-alignment)
17. [Downstream Application Opportunities](#17-downstream-application-opportunities)
18. [Glossary](#18-glossary)

---

## 1. Executive Summary

The **Real-Time AppSec Intelligence Platform** is a production-grade data engineering system that continuously monitors software dependency changes, ingests newly published CVEs in near real-time, and joins these two streams in Apache Flink (Python) to detect vulnerable dependencies across all services the moment a vulnerability is disclosed.

An AI agent layer built on LangGraph and Ollama (locally) or Anthropic Claude (production) triages every match automatically — fetching the affected source code, assessing whether the vulnerability is actually exploitable, scoring blast radius, and generating a complete remediation report. Results are exposed via an MCP server queryable from VS Code (Cline extension), stored in PostgreSQL, and delivered via Slack notifications.

**The core problem this solves:** Security teams currently rely on nightly or weekly batch vulnerability scans, creating detection lag measured in days. This platform treats vulnerability detection as a streaming problem. Detection lag drops from days to minutes.

### Design Philosophy — Local-First

The platform is designed to run entirely on a developer's machine using free, open-source tooling. There are no cloud service dependencies in the default configuration.

| Concern | Local (Default) | Production Upgrade |
|---------|----------------|-------------------|
| Object storage | MinIO (Docker) | AWS S3 / GCS |
| LLM inference | Ollama | Anthropic Claude Sonnet |
| Embeddings | Ollama `nomic-embed-text` | OpenAI `text-embedding-3-large` |
| Message bus | Redpanda (Docker) | Confluent Cloud / MSK |
| Stream processing | Flink local cluster (Docker) | Flink on Kubernetes |
| Vector database | Qdrant (Docker) | Qdrant Cloud |
| Relational database | PostgreSQL (Docker) | RDS / Cloud SQL |
| MCP client | VS Code + Cline extension | Claude Desktop or any MCP client |

All production upgrades are configuration changes only. No application code changes are required.

### Technology Stack Summary

| Layer | Technology | Language |
|-------|-----------|---------|
| Ingestion | net/http, confluent-kafka-go | Go |
| Message bus | Redpanda (Kafka-compatible) | — |
| Stream processing | Apache Flink 1.18 (PyFlink) | Python |
| AI orchestration | LangGraph | Python |
| LLM inference (local) | Ollama `qwen2.5-coder:7b` | — |
| LLM inference (production) | Anthropic Claude Sonnet | — |
| Vector database | Qdrant | — |
| MCP server | Python MCP SDK | Python |
| MCP client | VS Code + Cline extension | — |
| Object storage | MinIO | — |
| Audit store | Apache Iceberg on MinIO | — |
| Relational database | PostgreSQL 15 | — |
| Cache | Redis 7 | — |
| Observability | Prometheus + Grafana | — |
| Infrastructure | Docker Compose | — |

---

## 2. Business Objective

### 2.1 Problem Statement

Software vulnerabilities are disclosed at 150 to 300 CVEs per day, with spikes exceeding 100 per hour during coordinated vendor patch events. Current tooling addresses this problem inadequately:

- Vulnerability scanners run nightly or weekly, creating detection lag measured in days
- Scan results are not contextualised to actual code usage, generating alerts for unreachable code paths
- No automated prioritisation by blast radius — a CVE in a low-traffic internal tool receives the same alert weight as one in a customer-facing payment service
- Compliance evidence is assembled manually during audits rather than captured continuously
- Security knowledge is siloed — engineers cannot query live vulnerability state from their development environment

### 2.2 Business Goals

| Goal | Success Metric |
|------|---------------|
| Reduce mean time to detect (MTTD) for critical vulnerabilities | Under 10 minutes from CVE publication to triaged alert (production) |
| Eliminate false-positive alert fatigue | Exploitability confirmed before any alert is raised |
| Automate remediation guidance | Exact fix command generated with every alert |
| Continuous compliance evidence | Immutable audit log maintained automatically |
| Developer-native security access | Engineers query live security state from VS Code |

### 2.3 Target Users

| User | Primary Need |
|------|-------------|
| Security Engineers | Real-time vulnerability feed with exploitability context |
| Platform / SRE Teams | Service-level exposure visibility and remediation SLAs |
| Software Developers | Inline dependency risk warnings before code is merged |
| Engineering Managers | Team-level security posture and backlog prioritisation |
| Compliance Officers | Continuous audit evidence mapped to regulatory frameworks |

### 2.4 Commercial Context

The combination of PyFlink stream processing, agentic AI triage, and MCP-based delivery addresses a genuine gap in the AppSec tooling market. Existing solutions such as Snyk, Dependabot, and GitHub Advanced Security operate in batch mode with no real-time stream processing and limited AI-driven triage. This architecture applies to SaaS security vendors, enterprise platform teams, MSSPs, and organisations under continuous compliance obligations including PCI DSS, HIPAA, and SOC 2.

---

## 3. System Overview

### 3.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER (Go)                         │
│                                                                     │
│  NVD Poller · OSV Poller · GitHub Events API Poller                 │
│  GitHub Archive Replayer · Synthetic Generator                      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Redpanda / Kafka      │
                    │   (local event bus)     │
                    └───────────┬────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                  STREAM PROCESSING LAYER (PyFlink)                   │
│                                                                     │
│  Normaliser → Deduplicator → Manifest Parser → Dependency Graph     │
│  → CVE Join → Transitive Resolver → Blast Radius Scorer → Router   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Redpanda / Kafka      │
                    │   (enriched events)     │
                    └───────────┬────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                    AI AGENT LAYER (Python / LangGraph)               │
│                                                                     │
│  Triage Agent · PR Risk Agent · Security Posture Agent              │
│                                                                     │
│  Local:       Ollama (qwen2.5-coder:7b-instruct-q4_K_M)            │
│  Production:  Anthropic Claude Sonnet                               │
│                                                                     │
│  RAG: Qdrant (local Docker) + Ollama nomic-embed-text               │
└──────────┬────────────────────┬────────────────────────┬────────────┘
           │                    │                        │
    ┌──────▼──────┐   ┌─────────▼───────┐    ┌──────────▼─────────┐
    │  MCP Server │   │  Kafka Output   │    │   Storage Layer     │
    │  (Python)   │   │  Topics         │    │   PG · MinIO · Redis│
    └──────┬──────┘   └─────────────────┘    └────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────────┐
│                       DELIVERY LAYER                                 │
│                                                                     │
│  VS Code + Cline (MCP) · Slack Bot · Grafana Dashboard             │
│  GitHub Actions PR Gate                                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 How the Layers Fit Together

Each layer solves a distinct problem:

**Flink** solves the detection problem — finding CVE matches across live dependency graphs at scale, with exactly-once processing guarantees. This is a data engineering problem.

**The agent layer** solves the interpretation problem — turning a raw match event into a contextualised, actionable, human-readable triage report. This is an AI reasoning problem.

**The MCP server** solves the delivery problem — making all accumulated security intelligence queryable from the tools engineers already use, via natural language.

Neither layer is sufficient alone. Flink without the agent produces a flood of uncontextualised alerts that engineers still have to manually investigate. The agent without Flink would be too slow and too expensive to run against every dependency continuously. Together, the engineering layer handles scale and precision while the AI layer handles judgment and communication.

---

## 4. Data Sources and Throughput

### 4.1 Throughput Reality

Understanding the realistic data volumes from each source is critical for making informed decisions about when to use the archive replayer and synthetic generator.

```
Source                              Events/day      Events/hour    Authentic
──────────────────────────────────────────────────────────────────────────
NVD CVE feed (polled)               ~200            ~8             Yes
OSV.dev feed (polled)               ~200            ~8             Yes
GitHub Events API (15 repos)        300–500         15–25          Yes
──────────────────────────────────────────────────────────────────────────
Steady-state total                  700–900/day     30–40/hour     All real

GitHub Archive replayer (100x)      Millions        5,000–50,000   Real, replayed
Synthetic generator (hum mode)      ~170,000        ~7,000         Simulated
```

Real sources at steady state are sufficient to build and validate the entire pipeline. The archive replayer and synthetic generator serve specific, distinct purposes described in Sections 4.5 and 5.5.

### 4.2 NVD — National Vulnerability Database

```
Provider:    NIST
URL:         https://services.nvd.nist.gov/rest/json/cves/2.0
Protocol:    REST — polled every 5 minutes
Auth:        Free API key (50 req/30s authenticated, 5 req/30s unauthenticated)
Volume:      150–300 CVEs/day, spikes to 100+/hour on patch Tuesday
Format:      JSON — CVE records with CVSS scores, CWE classification, CPE strings
Kafka out:   vulns.nvd.raw
```

Note: NVD's CPE-based package identification requires fuzzy matching to join against ecosystem package names. OSV is preferred for the Flink join; NVD is used for CVSS scores and CWE classification.

### 4.3 OSV.dev — Open Source Vulnerability Database

```
Provider:    Google Open Source Security
URL:         https://api.osv.dev/v1/query
Bulk:        https://osv-vulnerabilities.storage.googleapis.com (GCS, updated every 6h)
Protocol:    REST point queries + GCS bulk export
Auth:        None required
Volume:      ~200 vulns/day
Format:      JSON — package name, ecosystem, semantic version range constraints
Kafka out:   vulns.osv.raw
```

OSV maps directly to `(package_name, ecosystem, version_range)` tuples, making the Flink CVE join trivial compared to NVD's CPE strings. OSV also provides broader ecosystem coverage including Go, Rust/Cargo, and Ruby, which NVD covers poorly.

**OSV version matching in the Flink join:**

```python
# OSV gives you this — directly joinable:
package.name      = "requests"
package.ecosystem = "PyPI"
ranges[0].events  = [{"introduced": "0"}, {"fixed": "2.32.0"}]
versions          = ["2.28.0", "2.28.1", ...]   # full list of affected versions

# Join becomes:
if dep.package_name == vuln.package.name \
   and dep.ecosystem.lower() == vuln.package.ecosystem.lower() \
   and dep.version in vuln.affected_versions:
       emit_match()
```

### 4.4 GitHub Events API — Real-Time Dependency Changes

```
Protocol:    REST polling — GET /repos/{owner}/{repo}/events every 60 seconds
Auth:        Personal access token (5,000 requests/hour authenticated)
Volume:      300–500 dependency-related PR events/day across 15 repos
Rate limit:  15 repos × 1 poll/minute = 900 requests/hour — well within limits
Kafka out:   deps.changes
```

Rather than GitHub webhooks (which require admin access to target repos), the Events API is polled every 60 seconds across 15 high-activity open source repositories. The majority of dependency bump PRs come from Dependabot and Renovate bots, which use highly consistent and parseable title formats.

**Recommended target repositories:**

| Repo | Ecosystem | Dep PRs/week | Why |
|------|-----------|-------------|-----|
| psf/requests | PyPI | 15–25 | Ironic — often the vulnerable package itself |
| django/django | PyPI | 20–30 | High Dependabot activity |
| fastapi/fastapi | PyPI | 15–25 | Modern Python, active deps |
| encode/httpx | PyPI | 10–20 | Active security-conscious maintainers |
| apache/airflow | PyPI + npm | 30–50 | Multi-ecosystem, high volume |
| pydantic/pydantic | PyPI | 15–25 | Core Python library |
| vercel/next.js | npm | 40–60 | Highest npm Dependabot activity |
| microsoft/vscode | npm | 30–50 | Massive dependency tree |
| expressjs/express | npm | 15–20 | npm ecosystem anchor |
| nodejs/node | npm | 25–40 | Core runtime |
| kubernetes/kubernetes | Go | 50–80 | Highest Go dep volume anywhere |
| hashicorp/terraform | Go | 20–30 | Active Go module updates |
| renovatebot/renovate | Multi | 100+ | Eats its own dog food heavily |
| home-assistant/core | PyPI | 40–60 | Large Python dependency surface |
| pallets/flask | PyPI | 10–15 | Flask ecosystem anchor |

**Branch name ecosystem detection (reliable for Dependabot PRs):**

```python
BRANCH_ECOSYSTEM_MAP = {
    r"dependabot/pip/":          "pypi",
    r"dependabot/npm_and_yarn/": "npm",
    r"dependabot/go_modules/":   "go",
    r"dependabot/maven/":        "maven",
    r"dependabot/cargo/":        "cargo",
    r"dependabot/bundler/":      "rubygems",
}

DEPENDABOT_TITLE_PATTERNS = [
    r"[Bb]ump (?P<pkg>[\w\-\.]+) from (?P<from>[\d\.]+) to (?P<to>[\d\.]+)",
    r"chore\(deps\).*bump (?P<pkg>[\w\-\.]+) from (?P<from>[\d\.]+) to (?P<to>[\d\.]+)",
    r"[Uu]pdate (?P<pkg>[\w\-\.]+) requirement from .* to .*(?P<to>[\d\.]+)",
]
```

### 4.5 GitHub Archive — Historical Bulk Replay

```
Provider:    GH Archive (gharchive.org)
URL:         https://data.gharchive.org/{YYYY-MM-DD}-{H}.json.gz
Protocol:    HTTP bulk download — one gzipped NDJSON file per hour
Volume:      3–5 million events per hour (all public GitHub activity)
Auth:        None required
Date range:  2024-01-01 onwards only — earlier data has outdated package
             versions that do not match current CVEs, and pre-2019 data
             predates go.mod, package-lock.json, and Dependabot entirely
```

The archive replayer operates in three distinct modes:

**Mode 1: SEED (runs once at startup)**
Replays 2024-01-01 to present at 100x speed to rapidly populate the Flink dependency graph state. Takes approximately 15–30 minutes. Exits cleanly when complete and hands off to the live GitHub Events API poller. This solves the cold start problem — without it, the Flink dependency graph is empty when the pipeline starts and CVE matches cannot fire.

**Mode 2: LOAD TEST (run on demand)**
Replays a configurable date window at maximum throughput to stress test the Flink topology. Run once the pipeline is complete to generate the throughput demonstration for portfolio purposes. At 100x replay speed, a single hour of 2024 archive data produces approximately 5,000–50,000 dependency change events per second through Flink.

**Mode 3: CONTINUOUS (optional)**
Replays the previous day's archive, waits 24 hours, then replays the next day. Simulates a continuously active engineering organisation without requiring real webhook subscriptions.

**Archive event filtering — only emit to Kafka if all conditions met:**

```python
event.type == "PullRequestEvent"
AND event.payload.action == "closed"
AND event.payload.pull_request.merged == True
AND event.payload.pull_request.merged_at >= "2024-01-01"
AND (
    re.search(r"dependabot/", event.payload.pull_request.head.ref)
    OR re.search(DEPENDABOT_TITLE_PATTERN, event.payload.pull_request.title)
)
# Filters 3–5M events/hour down to ~5,000–15,000 quality dep change events/hour
```

### 4.6 Deps.dev — Transitive Dependency Resolution

```
Provider:    Google Open Source Insights
URL:         https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{name}/versions/{version}
Protocol:    REST on-demand (called by Flink transitive resolver operator)
Auth:        None required
Purpose:     Resolve transitive dependency trees to catch indirect vulnerabilities
Caching:     Redis, TTL 3600s, key: {ecosystem}:{package}:{version}
```

---

## 5. Ingestion Layer — Go

All ingestion services are independent Go binaries sharing common Kafka producer configuration, event schemas, and Prometheus metrics setup from `ingestion/shared/`.

### 5.1 NVD Poller

**Binary:** `ingestion/nvd-poller/main.go`

- Polls every 300 seconds (configurable via `NVD_POLL_INTERVAL`)
- Cursor stored in Redis key: `nvd:cursor:last_pub_date`
- Paginates using `pubStartDate` / `pubEndDate` window queries
- Exponential backoff on rate limits: initial 1s, max 60s, multiplier 2.0
- Publishes to `vulns.nvd.raw` with CVE ID as partition key

```bash
NVD_API_KEY=<free key from nvd.nist.gov>
NVD_POLL_INTERVAL=300
KAFKA_BROKERS=localhost:9092
REDIS_ADDR=localhost:6379
```

### 5.2 OSV Poller

**Binary:** `ingestion/osv-poller/main.go`

- Initial bulk corpus load from GCS on cold start (flag: Redis key `osv:bulk_loaded`)
- Incremental polling every 600 seconds using `modified` field for delta detection
- Publishes to `vulns.osv.raw` and `corpus.osv.bulk` (for RAG indexing)

### 5.3 GitHub Events API Poller

**Binary:** `ingestion/github-events-poller/main.go`

- Polls all 15 target repos every 60 seconds
- 15 repos × 1 poll/minute = 900 requests/hour (within 5,000/hour limit)
- Filters to merged PRs touching dependency files
- Extracts package and version from Dependabot branch name and PR title
- Publishes to `deps.changes`

```bash
GITHUB_TOKEN=<personal access token>
KAFKA_BROKERS=localhost:9092
REDIS_ADDR=localhost:6379
TARGET_REPOS=psf/requests,django/django,fastapi/fastapi,...
```

### 5.4 GitHub Archive Replayer

**Binary:** `ingestion/archive-replayer/main.go`

```
Flags:
  --start-date    YYYY-MM-DD    required (minimum: 2024-01-01)
  --end-date      YYYY-MM-DD    required
  --speed         float         default=100.0 (1.0 = real time, 100.0 = 100x)
  --mode          string        seed | loadtest | continuous
  --kafka-brokers string        required

Behaviour:
  Downloads hourly .json.gz files from data.gharchive.org
  Decompresses and parses NDJSON line by line (streaming, not into memory)
  Applies archive event filter (merged Dependabot PRs, 2024+ only)
  Emits DependencyChangeEvents to deps.changes at controlled rate
  In seed mode: exits when date range exhausted
  In continuous mode: loops indefinitely, replaying one day at a time
```

### 5.5 Synthetic Generator

**Container:** `scripts/synthetic-generator/` (Python, separate Docker container)

The synthetic generator serves a specific purpose that neither the archive replayer nor the Events API can provide: **on-demand scenario triggering for demonstrations**. It runs persistently alongside the live pipeline and allows specific CVE scenarios to be fired at any time.

It has three responsibilities:

**Background hum** — emits realistic dependency change events at 2 events/second continuously, keeping the pipeline visually active between demos.

**Registry seeder** — on first startup, seeds PostgreSQL with a realistic service registry of 50 microservices across 5 teams. This registry is what the blast radius scorer and triage agent query to determine service criticality, compliance scope, and PII handling.

**Scenario injector** — exposes a simple CLI and optional web UI at `localhost:8090` to fire named demo scenarios on demand.

**The 50-service registry covers:**

```
Payments team (PCI DSS scope):
  checkout-api, payment-processor, invoice-generator,
  fraud-detector, billing-scheduler

Auth / Platform team:
  auth-service, session-manager, permissions-api,
  api-gateway, config-service, secrets-manager,
  log-aggregator, metrics-collector

Product team:
  user-api, notification-worker, search-api,
  recommendations-api

Frontend team (npm):
  storefront, admin-portal, mobile-bff

Data team:
  data-pipeline, reporting-service, ml-training-worker,
  feature-store-api

Legacy / Java (Maven):
  legacy-billing, document-processor
```

Approximately 30% of services are seeded with known-vulnerable dependency versions so the pipeline fires end-to-end without requiring scenario injection.

**Named demo scenarios:**

| Scenario | Description | Expected Pipeline Outcome |
|----------|-------------|--------------------------|
| `critical_rce` | RCE CVE in `requests < 2.32.0` affecting 3 customer-facing services | 3 CRITICAL triage reports, Slack alerts to payments + platform teams |
| `mass_exposure` | `cryptography < 42.0.4` affecting 8 services across 4 teams | Demonstrates blast radius scoring and team-level alert routing |
| `supply_chain_attack` | PR opened adding `PyYAML==5.3.1` (known vulnerable) | PR Risk Agent posts BLOCK verdict before merge |
| `log4shell_redux` | Log4j 1.2.17 + Spring4Shell in legacy Java service | Demonstrates Maven ecosystem and multi-CVE detection |
| `safe_upgrade_wave` | Dependabot upgrades 10 services to safe `requests==2.32.1` | No alerts — demonstrates correct non-firing behaviour |
| `pr_risk_safe` | PR adding `httpx==0.27.0` (no known CVEs) | PR Risk Agent posts APPROVE verdict |

---

## 6. Stream Processing Layer — PyFlink

Single PyFlink job in `stream-processing/topology.py`, composed of 8 operators in `stream-processing/operators/`. Uses the DataStream API with RocksDB state backend and exactly-once checkpointing to MinIO.

### 6.1 Flink Configuration

```python
env = StreamExecutionEnvironment.get_execution_environment()
env.set_parallelism(4)
env.enable_checkpointing(60_000)  # 60 second interval
env.get_checkpoint_config().set_checkpointing_mode(CheckpointingMode.EXACTLY_ONCE)
env.set_state_backend(EmbeddedRocksDBStateBackend())

# Checkpoint storage: MinIO via S3-compatible protocol
# Required flink-conf.yaml settings:
#   s3.endpoint: http://minio:9000
#   s3.path.style.access: true
#   s3.access-key: minioadmin
#   s3.secret-key: minioadmin
env.get_checkpoint_config().set_checkpoint_storage(
    FileSystemCheckpointStorage("s3://flink-checkpoints/appsec")
)
```

### 6.2 Operator Specifications

#### Operator 1: Normalisation

**File:** `stream-processing/operators/normaliser.py`

Maps all three source formats to canonical internal schemas:
- NVD JSON → `VulnerabilityEvent`
- OSV JSON → `VulnerabilityEvent`
- GitHub event / archive event → `DependencyChangeEvent`

Parses CVSS score to severity tier: `CRITICAL (>=9.0) | HIGH (7.0–8.9) | MEDIUM (4.0–6.9) | LOW (<4.0)`

#### Operator 2: Deduplication

**File:** `stream-processing/operators/deduplicator.py`

- State backend: RocksDB, TTL: 24 hours
- Key: `sha256(cve_id + package_name + ecosystem + version)`
- Silently discards duplicates — NVD and OSV frequently publish the same CVE

#### Operator 3: Manifest Parser

**File:** `stream-processing/operators/manifest_parser.py`

| Ecosystem | Files | Parser |
|-----------|-------|--------|
| PyPI | requirements.txt, pyproject.toml | `requirements-parser`, `tomllib` |
| npm | package.json, package-lock.json | `json.loads` |
| Maven | pom.xml | `xml.etree.ElementTree` |
| Go | go.mod | regex line parser |
| Cargo | Cargo.toml | `tomllib` |
| RubyGems | Gemfile.lock | regex line parser |

For archive events where the file diff is unavailable, package and version are extracted from the PR title and branch name using Dependabot/Renovate regex patterns.

#### Operator 4: Dependency Graph

**File:** `stream-processing/operators/dependency_graph.py`

- State: `MapState[service_id → ServiceDependencyGraph]` (RocksDB)
- Applies `DependencyChangeEvent` deltas to maintain live per-service dependency snapshots
- Emits updated snapshots to `vuln.graph.snapshots`

```python
@dataclass
class ServiceDependencyGraph:
    service_id:   str
    ecosystem:    str
    dependencies: dict[str, str]     # package_name → pinned_version
    metadata:     ServiceMetadata

@dataclass
class ServiceMetadata:
    is_customer_facing: bool
    compliance_scope:   list[str]    # pci_dss | hipaa | soc2 | iso27001
    pii_handler:        bool
    last_updated:       datetime
    code_owners:        list[str]
    team:               str
```

#### Operator 5: CVE Join

**File:** `stream-processing/operators/cve_join.py`

- Type: `BroadcastProcessFunction`
- CVE stream broadcast to all parallel instances
- On each incoming CVE: iterates full dependency graph state for matches
- Version matching: ecosystem-native semver libraries (`packaging.specifiers` for PyPI, semver for npm, etc.)

#### Operator 6: Transitive Resolver

**File:** `stream-processing/operators/transitive_resolver.py`

- Type: `AsyncFunction` (non-blocking IO)
- Calls deps.dev API to resolve transitive dependency trees
- Redis cache: key `{ecosystem}:{package}:{version}`, TTL 3600 seconds

#### Operator 7: Blast Radius Scorer

**File:** `stream-processing/operators/blast_radius_scorer.py`

```python
# Composite score weights
CVSS_WEIGHT            = 0.40    # Base vulnerability severity
CUSTOMER_FACING_WEIGHT = 0.25    # Is this service public-facing?
COMPLIANCE_WEIGHT      = 0.20    # Is it in PCI DSS / HIPAA / SOC 2 scope?
PII_HANDLER_WEIGHT     = 0.15    # Does it process personal data?

# Blast radius tier thresholds
# CRITICAL >= 0.75 | HIGH 0.50–0.74 | MEDIUM 0.25–0.49 | LOW < 0.25
```

#### Operator 8: Router

**File:** `stream-processing/operators/router.py`

| Condition | Output Topic | Remediation SLA |
|-----------|-------------|----------------|
| CRITICAL blast radius | `vuln.matches.critical` | 4 hours |
| HIGH blast radius | `vuln.matches.high` | 24 hours |
| MEDIUM blast radius | `vuln.matches.medium` | 7 days |
| LOW blast radius | `vuln.matches.low` | Next sprint |
| PR with new vulnerable dep | `deps.risk.prs` | Pre-merge |
| Dependency graph updated | `vuln.graph.snapshots` | Continuous |

---

## 7. AI Agent Layer

Three LangGraph agents consume from Kafka, use RAG to gather context, call external tools for evidence, synthesise findings via an LLM, and emit structured outputs.

### 7.1 LLM Provider Abstraction

All agents import from a single `agents/llm_provider.py` module. No agent imports directly from `langchain_ollama` or `langchain_anthropic`. Switching between local (Ollama) and production (Claude) requires only environment variable changes.

```python
# agents/llm_provider.py

import os
from langchain_core.language_models import BaseChatModel
from langchain_core.embeddings import Embeddings

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")  # ollama | anthropic

def get_llm(temperature: float = 0.0) -> BaseChatModel:
    if LLM_PROVIDER == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            temperature=temperature,
        )
    elif LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20251001"),
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=temperature,
        )
    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")

def get_embeddings() -> Embeddings:
    if LLM_PROVIDER == "ollama":
        from langchain_ollama import OllamaEmbeddings
        return OllamaEmbeddings(
            model=os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )
    elif LLM_PROVIDER == "anthropic":
        from langchain_openai import OpenAIEmbeddings
        return OpenAIEmbeddings(
            model="text-embedding-3-large",
            api_key=os.getenv("OPENAI_API_KEY"),
        )
    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")
```

**Environment variables — local (default):**

```bash
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5-coder:7b-instruct-q4_K_M
OLLAMA_EMBED_MODEL=nomic-embed-text
OLLAMA_BASE_URL=http://localhost:11434
```

**Environment variables — production (change only these):**

```bash
LLM_PROVIDER=anthropic
ANTHROPIC_MODEL=claude-sonnet-4-5-20251001
ANTHROPIC_API_KEY=<key>
OPENAI_API_KEY=<key>
```

### 7.2 Ollama Model Recommendations

Hardware context: MacBook M2 Pro, 16GB unified RAM.

```
RAM budget:
  macOS + Docker stack overhead:  ~5–6GB
  Available for Ollama model:     ~10GB

Recommended models:

  Primary reasoning (qwen2.5-coder:7b-instruct-q4_K_M):
    RAM:         ~4.5GB
    Why:         Trained on code — superior at reading Python imports,
                 function call patterns, and dependency graphs compared
                 to general models. Strong structured JSON output.
                 Fits comfortably alongside the full Docker stack.

  Alternative (llama3.1:8b-instruct-q4_K_M):
    RAM:         ~5GB
    Why:         Stronger general reasoning, slightly weaker on code
                 analysis specifically. Good fallback.

  Embeddings (nomic-embed-text):
    RAM:         ~274MB
    Why:         Fast, high-quality embeddings. Required for RAG.
                 Negligible footprint.

  Do not use on 16GB with full Docker stack:
    Any 14B+ model — leaves insufficient RAM for Flink, Postgres,
    Qdrant, Redis, and Redpanda running simultaneously.

Pull commands:
  ollama pull qwen2.5-coder:7b-instruct-q4_K_M
  ollama pull nomic-embed-text
```

On Apple Silicon, Ollama automatically uses Metal for GPU acceleration, yielding approximately 30–50 tokens/second with the recommended model.

**Important note on output quality:** A 7B model produces triage reports of lower nuance than Claude Sonnet. This is mitigated by design — the LLM only performs the final synthesis step. All evidence gathering (code fetching, OSV queries, RAG retrieval) is done deterministically before the LLM is invoked. The model reasons over well-structured, pre-gathered evidence rather than from general knowledge.

### 7.3 RAG Knowledge Base

**Vector database:** Qdrant (local Docker)
**Embedding model:** `nomic-embed-text` via Ollama (local) / `text-embedding-3-large` (production)
**Chunk size:** 512 tokens with 64-token overlap

| Collection | Contents | Source | Update Frequency |
|------------|----------|--------|-----------------|
| `cve_descriptions` | CVE text, CWE descriptions, attack narratives | NVD + OSV feed | Real-time |
| `exploit_reports` | PoC exploit write-ups, vulnerability research | GitHub Archive corpus | Batch daily |
| `remediation_guides` | Package changelogs, security fix commit messages | GitHub Archive corpus | Batch daily |
| `architecture_docs` | Service topology, CODEOWNERS, compliance scope | Synthetic registry | On change |
| `incident_postmortems` | Historical security incidents from public repos | GitHub Archive corpus | Batch daily |
| `regulatory_frameworks` | PCI DSS, HIPAA, SOC 2, OWASP, NIST CSF controls | Public documents | Manual quarterly |

### 7.4 Vulnerability Triage Agent

**File:** `agents/triage/agent.py`
**Trigger:** Kafka consumer on `vuln.matches.critical` and `vuln.matches.high`
**Output:** `TriageReport` → Kafka `vuln.triaged` + PostgreSQL

The agent follows a multi-step reasoning process where the LLM is only invoked at the final synthesis step. All preceding steps are deterministic tool calls and RAG retrievals.

#### 7.4.1 LangGraph Node Sequence

```
START
  │
  ▼
retrieve_cve_context
  RAG query: cve_descriptions + exploit_reports
  Builds understanding of the CVE before any code analysis
  │
  ▼
fetch_affected_files
  Tool: github_fetch_file()
  Fetches all files in the affected service that import the vulnerable package
  │
  ▼
assess_exploitability
  LLM + retrieved context:
  "Is the vulnerable code path actually called in these files?"
  Verdict: CONFIRMED | LIKELY | UNLIKELY | NOT_AFFECTED
  │
  ├── if NOT_AFFECTED → END (no report generated, no alert)
  │
  ▼
retrieve_blast_radius
  RAG query: architecture_docs + regulatory_frameworks
  Fetches service compliance scope, downstream dependencies
  │
  ▼
fetch_remediation_path
  Tool: osv_query() → safe version range
  Tool: deps_dev_lookup() → compatibility with existing pins
  │
  ▼
generate_triage_report
  LLM synthesis over all gathered evidence → TriageReport JSON
  │
  ▼
emit_output
  Write to Kafka vuln.triaged + PostgreSQL triage_reports
  │
  ▼
END
```

#### 7.4.2 Tools

```python
# agents/tools/github.py
@tool
def github_fetch_file(repo: str, path: str, sha: str) -> FileContent:
    """Fetch file content from GitHub at a specific commit SHA for code analysis."""

# agents/tools/osv.py
@tool
def osv_query(package: str, version: str, ecosystem: str) -> OSVQueryResult:
    """Query OSV.dev for vulnerability details and safe version ranges."""

# agents/tools/deps_dev.py
@tool
def deps_dev_lookup(package: str, version: str, ecosystem: str) -> DepsDevResult:
    """Resolve full transitive dependency tree and verify upgrade compatibility."""

# agents/tools/qdrant.py
@tool
def qdrant_search(query: str, collection: str, top_k: int = 5) -> list[Document]:
    """Semantic search over the specified RAG collection."""

# agents/tools/service_registry.py
@tool
def get_service_metadata(service_id: str) -> ServiceMetadata:
    """Retrieve service compliance scope, customer-facing status, PII flag."""

@tool
def get_code_owners(repo: str, file_path: str) -> list[str]:
    """Retrieve CODEOWNERS entries for alert routing and assignment."""
```

#### 7.4.3 TriageReport Output Schema

```python
@dataclass
class TriageReport:
    report_id:    str
    cve_id:       str
    service_id:   str
    generated_at: datetime

    # Exploitability assessment
    exploitability_verdict:    str         # CONFIRMED | LIKELY | UNLIKELY | NOT_AFFECTED
    exploitability_rationale:  str
    vulnerable_locations:      list[CodeLocation]  # file, line, function

    # Blast radius
    blast_radius_tier:             str     # CRITICAL | HIGH | MEDIUM | LOW
    blast_radius_rationale:        str
    downstream_services_at_risk:   list[str]
    compliance_controls_at_risk:   list[str]  # e.g. ["PCI DSS CC6.1", "SOC2 CC7.1"]

    # Remediation
    remediation_action:   str              # e.g. "pip install requests==2.32.1"
    safe_version:         str
    is_breaking_change:   bool
    estimated_effort_hours: float
    compatibility_notes:  str

    # Assignment
    sla_deadline:    datetime
    assigned_to:     str
    assigned_team:   str

    # Metadata
    confidence_score: float                # 0.0–1.0
    sources_cited:    list[str]
    llm_provider:     str                  # e.g. "ollama:qwen2.5-coder:7b"
```

#### 7.4.4 System Prompt

```
You are a senior application security engineer performing vulnerability triage.

You have been provided with:
- A vulnerability match event identifying a CVE affecting a specific service
- Retrieved CVE documentation and known exploit reports from the knowledge base
- The actual source code files that import the vulnerable package
- Service architecture context including compliance scope and downstream dependencies
- Remediation data from OSV.dev and deps.dev

Your task is to produce a TriageReport with the following properties:

1. EXPLOITABILITY: Determine whether the vulnerable code path is actually
   called in the retrieved source files. Cite the exact file, line number,
   and function name. Do not speculate beyond what the code evidence supports.
   If you cannot confirm the vulnerability is reachable, say UNLIKELY.

2. BLAST RADIUS: Assess real-world impact given the service's compliance scope
   and customer-facing status. Reference the specific regulatory controls at risk.

3. REMEDIATION: Provide the exact upgrade command. Verify compatibility with
   existing dependency pins before recommending. Note any breaking changes.

4. All factual claims must cite their source document. Do not draw on general
   knowledge when a retrieved document is available.

5. Assign a confidence score between 0.0 and 1.0 based on the completeness
   of the evidence you were given.

Output ONLY a valid JSON object matching the TriageReport schema. No preamble,
no explanation outside the JSON structure.
```

### 7.5 PR Risk Agent

**File:** `agents/pr_risk/agent.py`
**Trigger:** Kafka consumer on `deps.risk.prs`
**Output:** GitHub PR review comment + `PRRiskVerdict` → PostgreSQL

```
Node sequence (sequential):
  check_direct_vulnerabilities  → osv_query() for each new package
  retrieve_package_history      → RAG: cve_descriptions filtered by package name
  assess_maintenance_health     → deps_dev_lookup(): maintainer count, last release
  check_transitive_conflicts    → deps_dev_lookup(): conflict with existing graph
  generate_pr_comment           → LLM synthesis → structured PR comment
  post_github_comment           → GitHub API POST review comment
```

```python
@dataclass
class PRRiskVerdict:
    verdict:               str    # APPROVE | WARN | BLOCK
    risk_level:            str    # LOW | ELEVATED | CRITICAL
    summary:               str
    vulnerabilities:       list[VulnSummary]
    maintenance_risk:      str | None
    compatibility_issues:  list[str]
    recommended_action:    str
    github_status:         str    # success | failure
```

### 7.6 Security Posture Agent

**File:** `agents/posture/agent.py`
**Trigger:** Cron — daily at 06:00 UTC
**Output:** `PostureReport` → PostgreSQL + MinIO (Iceberg) + Kafka `posture.reports.daily`

```
Node sequence (sequential):
  query_vulnerability_metrics   → PostgreSQL: counts by tier, service, team, status
  compute_trend_analysis        → PostgreSQL: 7/30/90 day window comparisons
  identify_sla_breaches         → PostgreSQL: past-deadline open vulnerabilities
  generate_team_breakdown       → PostgreSQL: aggregate by code-owning team
  retrieve_compliance_controls  → RAG: regulatory_frameworks collection
  map_compliance_gaps           → LLM: map open vulns to specific control gaps
  generate_executive_narrative  → LLM: produce plain-English executive summary
  emit_posture_report           → PostgreSQL + MinIO Iceberg + Kafka write
```

---

## 8. MCP Server

**File:** `mcp-server/server.py`
**Client:** VS Code + Cline extension (primary), any MCP-compatible client
**Cache:** Redis, 60-second TTL on all tool responses

The MCP server is a thin query layer. It does not perform AI reasoning. It exposes structured access to PostgreSQL and Qdrant so that MCP-compatible clients can query live security intelligence in natural language.

### 8.1 Exposed Tools

```python
@tool
def get_vulnerability_exposure(service_id: str = None) -> dict:
    """All open vulnerabilities for a service or across all services,
    with triage status, SLA deadline, and assigned engineer."""

@tool
def get_cve_details(cve_id: str) -> dict:
    """Full triage report for a CVE: exploitability verdict, blast radius,
    code locations, and remediation instructions."""

@tool
def search_vulnerabilities(query: str) -> list[dict]:
    """Semantic search over all triaged vulnerability reports.
    Example queries: 'auth bypass in customer-facing services',
    'critical Python CVEs this week'"""

@tool
def get_remediation_path(package: str, version: str, ecosystem: str) -> dict:
    """Safest upgrade path including compatibility notes and effort estimate."""

@tool
def get_affected_services(cve_id: str) -> list[dict]:
    """All services affected by a CVE with blast radius scores and SLA status."""

@tool
def get_team_exposure(team_name: str) -> dict:
    """All open vulnerabilities owned by a team, sorted by SLA urgency."""

@tool
def get_compliance_gaps(framework: str) -> list[dict]:
    """Open vulnerabilities representing gaps in pci_dss | soc2 | hipaa | iso27001."""

@tool
def get_security_posture_summary() -> dict:
    """Most recent daily posture report with trend analysis and executive narrative."""

@tool
def get_dependency_graph(service_id: str) -> dict:
    """Current dependency snapshot for a service from Flink graph state."""
```

### 8.2 VS Code + Cline Configuration

In `.vscode/cline_mcp_config.json` or the Cline MCP settings panel:

```json
{
  "mcpServers": {
    "appsec-intelligence": {
      "command": "python",
      "args": ["mcp-server/server.py"],
      "env": {
        "POSTGRES_URL": "postgresql://appsec:appsec@localhost:5432/appsec",
        "QDRANT_URL": "http://localhost:6333",
        "REDIS_URL": "redis://localhost:6379"
      }
    }
  }
}
```

Once registered, you can query the platform from VS Code using natural language via the Cline panel:

```
"What vulnerabilities does the payments team need to fix today?"
"Is checkout-api affected by the new requests CVE?"
"Generate a remediation plan for all CRITICAL findings this week"
"What compliance controls are at risk from our open vulnerabilities?"
```

---

## 9. Storage Layer

### 9.1 MinIO — Local Object Storage

MinIO is an S3-compatible object storage server running in Docker. The application uses the boto3 S3 client with a custom endpoint — switching to AWS S3 in production requires only removing `AWS_ENDPOINT_URL` and updating credentials.

**Docker service:** see Section 10.1

**Buckets:**

| Bucket | Contents |
|--------|---------|
| `flink-checkpoints` | Flink RocksDB checkpoint files |
| `appsec-audit-log` | Apache Iceberg audit table data files |
| `appsec-rag-corpus` | Raw documents before embedding |
| `appsec-backups` | PostgreSQL dumps |

**boto3 client — works unchanged for MinIO and AWS S3:**

```python
import boto3, os

s3 = boto3.client(
    "s3",
    endpoint_url=os.getenv("AWS_ENDPOINT_URL"),       # None in production
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
```

**Local environment variables:**

```bash
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin
AWS_ENDPOINT_URL=http://localhost:9000
AWS_DEFAULT_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
```

**Production migration:** Remove `AWS_ENDPOINT_URL` and `S3_FORCE_PATH_STYLE`, update credentials. No code changes.

### 9.2 Apache Iceberg on MinIO — Audit Store

Iceberg tables stored in MinIO's `appsec-audit-log` bucket with a local Iceberg REST catalog container.

```sql
CREATE TABLE appsec_audit_events (
    event_date   date,
    event_id     string,
    event_type   string,    -- detection | triage | remediation | compliance_check
    cve_id       string,
    service_id   string,
    actor        string,
    action       string,
    details      string,    -- JSON
    created_at   timestamp
)
USING iceberg
PARTITIONED BY (event_date)
LOCATION 's3://appsec-audit-log/events';
```

### 9.3 PostgreSQL — Core Schema

```sql
CREATE TABLE vulnerabilities (
    cve_id           VARCHAR(20) PRIMARY KEY,
    cvss_score       DECIMAL(3,1),
    severity_tier    VARCHAR(10),
    description      TEXT,
    affected_package VARCHAR(200),
    ecosystem        VARCHAR(20),
    affected_range   VARCHAR(200),
    safe_version     VARCHAR(100),
    published_at     TIMESTAMPTZ,
    source           VARCHAR(10),    -- nvd | osv
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE vulnerability_matches (
    match_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id         VARCHAR(20) REFERENCES vulnerabilities(cve_id),
    service_id     VARCHAR(200),
    matched_version VARCHAR(100),
    blast_radius   VARCHAR(10),
    status         VARCHAR(20),    -- open | in_progress | resolved | accepted_risk
    sla_deadline   TIMESTAMPTZ,
    assigned_to    VARCHAR(100),
    assigned_team  VARCHAR(100),
    detected_at    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at    TIMESTAMPTZ
);

CREATE TABLE triage_reports (
    report_id                UUID PRIMARY KEY,
    match_id                 UUID REFERENCES vulnerability_matches(match_id),
    exploitability           VARCHAR(20),
    exploitability_rationale TEXT,
    blast_radius_rationale   TEXT,
    remediation_action       TEXT,
    is_breaking_change       BOOLEAN,
    estimated_effort_hours   DECIMAL(4,1),
    confidence_score         DECIMAL(3,2),
    sources_cited            JSONB,
    llm_provider             VARCHAR(100),
    generated_at             TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE posture_reports (
    report_id        UUID PRIMARY KEY,
    generated_at     TIMESTAMPTZ DEFAULT NOW(),
    period_days      INTEGER,
    open_critical    INTEGER,
    open_high        INTEGER,
    open_medium      INTEGER,
    open_low         INTEGER,
    past_sla_count   INTEGER,
    mttd_minutes     DECIMAL(8,2),
    mttr_days        DECIMAL(8,2),
    trend_direction  VARCHAR(20),
    executive_summary TEXT,
    compliance_gaps  JSONB,
    team_exposure    JSONB
);

CREATE TABLE service_registry (
    service_id       VARCHAR(200) PRIMARY KEY,
    team             VARCHAR(100),
    ecosystem        VARCHAR(20),
    is_customer_facing BOOLEAN,
    pci_scope        BOOLEAN,
    hipaa_scope      BOOLEAN,
    soc2_scope       BOOLEAN,
    pii_handler      BOOLEAN,
    description      TEXT,
    code_owners      JSONB
);

CREATE TABLE audit_log (
    log_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  VARCHAR(50),
    entity_id   VARCHAR(200),
    actor       VARCHAR(100),
    action      TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
```

### 9.4 Redis — Key Patterns

```
nvd:cursor:last_pub_date              NVD poller cursor
osv:bulk_loaded                       OSV initial bulk load flag (boolean)
deps_dev:cache:{ecosystem}:{pkg}:{v}  Deps.dev response (TTL: 3600s)
service_registry:{service_id}         Service metadata cache (TTL: 300s)
mcp:cache:{tool_name}:{args_hash}     MCP response cache (TTL: 60s)
```

---

## 10. Local Development Environment

The full platform runs locally with no cloud service dependencies. All services are defined in a single `docker-compose.yml`.

### 10.1 Docker Compose Stack

```yaml
services:

  redpanda:
    image: redpandadata/redpanda:latest
    ports: ["9092:9092", "8080:8080"]
    command: redpanda start --overprovisioned --smp 1 --memory 512M

  flink-jobmanager:
    image: apache/flink:1.18-python3
    ports: ["8081:8081"]
    environment:
      FLINK_PROPERTIES: "jobmanager.rpc.address=flink-jobmanager"
      AWS_ACCESS_KEY_ID: minioadmin
      AWS_SECRET_ACCESS_KEY: minioadmin
      S3_ENDPOINT: http://minio:9000
      S3_PATH_STYLE_ACCESS: "true"

  flink-taskmanager:
    image: apache/flink:1.18-python3
    depends_on: [flink-jobmanager]
    environment:
      FLINK_PROPERTIES: "jobmanager.rpc.address=flink-jobmanager"

  minio:
    image: minio/minio:latest
    ports: ["9000:9000", "9001:9001"]
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes: ["minio_data:/data"]

  minio-init:
    image: minio/mc:latest
    depends_on: [minio]
    entrypoint: >
      /bin/sh -c "
      mc alias set local http://minio:9000 minioadmin minioadmin &&
      mc mb local/flink-checkpoints &&
      mc mb local/appsec-audit-log &&
      mc mb local/appsec-rag-corpus &&
      mc mb local/appsec-backups
      "

  iceberg-rest:
    image: tabulario/iceberg-rest:latest
    ports: ["8181:8181"]
    environment:
      CATALOG_WAREHOUSE: s3://appsec-audit-log/
      CATALOG_IO__IMPL: org.apache.iceberg.aws.s3.S3FileIO
      CATALOG_S3_ENDPOINT: http://minio:9000
      CATALOG_S3_PATH__STYLE__ACCESS: "true"
      AWS_ACCESS_KEY_ID: minioadmin
      AWS_SECRET_ACCESS_KEY: minioadmin

  qdrant:
    image: qdrant/qdrant:latest
    ports: ["6333:6333"]
    volumes: ["qdrant_data:/qdrant/storage"]

  postgres:
    image: postgres:15
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: appsec
      POSTGRES_USER: appsec
      POSTGRES_PASSWORD: appsec
    volumes: ["postgres_data:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  ollama:
    image: ollama/ollama:latest
    ports: ["11434:11434"]
    volumes: ["ollama_data:/root/.ollama"]
    # Remove the deploy block if no GPU is available
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  prometheus:
    image: prom/prometheus:latest
    ports: ["9090:9090"]
    volumes: ["./infrastructure/prometheus.yml:/etc/prometheus/prometheus.yml"]

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes: ["grafana_data:/var/lib/grafana"]

  synthetic-generator:
    build: ./scripts/synthetic-generator
    depends_on: [redpanda, postgres]
    environment:
      KAFKA_BROKERS: redpanda:9092
      POSTGRES_URL: postgresql://appsec:appsec@postgres:5432/appsec
      HUM_RATE: "2.0"
      SEED_REGISTRY: "true"
    ports: ["8090:8090"]
    command: python main.py --mode hum

volumes:
  minio_data:
  qdrant_data:
  postgres_data:
  ollama_data:
  grafana_data:
```

### 10.2 First-Run Setup

```bash
# 1. Start all services
docker compose up -d

# 2. Pull Ollama models (run inside container or via local Ollama)
docker exec -it appsec-ollama-1 ollama pull qwen2.5-coder:7b-instruct-q4_K_M
docker exec -it appsec-ollama-1 ollama pull nomic-embed-text

# 3. Run database migrations
psql postgresql://appsec:appsec@localhost:5432/appsec \
  -f infrastructure/sql/schema.sql

# 4. Seed service registry (via synthetic generator)
docker exec appsec-synthetic-generator-1 python main.py --seed-only

# 5. Run archive replayer in seed mode (populates Flink dep graph)
go run ingestion/archive-replayer/main.go \
  --start-date 2024-01-01 \
  --end-date 2025-01-01 \
  --speed 100 \
  --mode seed \
  --kafka-brokers localhost:9092

# 6. Build initial RAG corpus
python scripts/corpus-builder/build_corpus.py --days 7

# 7. Start Go ingestion services
go run ingestion/nvd-poller/main.go &
go run ingestion/osv-poller/main.go &
go run ingestion/github-events-poller/main.go &

# 8. Submit PyFlink job
python stream-processing/topology.py

# 9. Start agent consumers
python agents/triage/consumer.py &
python agents/pr_risk/consumer.py &
python agents/posture/scheduler.py &

# 10. Start MCP server
python mcp-server/server.py

# Verify services:
open http://localhost:9001   # MinIO console    (minioadmin / minioadmin)
open http://localhost:8081   # Flink dashboard
open http://localhost:3000   # Grafana          (admin / admin)
open http://localhost:8090   # Scenario UI
```

### 10.3 Environment Variables

Copy `.env.example` to `.env` and populate:

```bash
# LLM
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5-coder:7b-instruct-q4_K_M
OLLAMA_EMBED_MODEL=nomic-embed-text
OLLAMA_BASE_URL=http://localhost:11434

# MinIO (local)
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin
AWS_ENDPOINT_URL=http://localhost:9000
AWS_DEFAULT_REGION=us-east-1
S3_FORCE_PATH_STYLE=true

# Kafka
KAFKA_BROKERS=localhost:9092

# Databases
POSTGRES_URL=postgresql://appsec:appsec@localhost:5432/appsec
QDRANT_URL=http://localhost:6333
REDIS_URL=redis://localhost:6379

# GitHub (real keys required)
GITHUB_TOKEN=<your personal access token>
NVD_API_KEY=<free key from nvd.nist.gov — no cost>
```

---

## 11. Observability

Prometheus and Grafana are included in the default Docker Compose stack. All services expose a `/metrics` endpoint.

### 11.1 Prometheus Metrics

```
# Ingestion
nvd_events_polled_total
osv_events_polled_total
github_events_fetched_total{repo}
archive_events_replayed_total
synthetic_events_emitted_total{scenario}

# Flink
flink_operator_records_in_total{operator}
flink_operator_records_out_total{operator}
flink_kafka_consumer_lag{topic, consumer_group}
flink_checkpoint_duration_ms

# Agents
agent_invocations_total{agent_name}
agent_duration_ms{agent_name, p50, p95, p99}
agent_errors_total{agent_name, error_type}
rag_retrieval_duration_ms{collection}
llm_tokens_used_total{provider, model}

# MCP
mcp_tool_calls_total{tool_name}
mcp_tool_duration_ms{tool_name}
mcp_cache_hit_ratio{tool_name}

# Storage
minio_bucket_size_bytes{bucket}
postgres_query_duration_ms{query_type}
```

### 11.2 Grafana Dashboards

**Dashboard 1 — Pipeline Health:**
Flink throughput (events/sec per operator), Kafka consumer lag per topic, checkpoint success rate, archive replayer progress, ingestion event rates by source.

**Dashboard 2 — Security Intelligence:**
Open vulnerabilities by severity tier over time, MTTD trend (30-day rolling), MTTR trend, SLA compliance rate by team, CVE match rate, blast radius distribution, triage report confidence score distribution.

**Dashboard 3 — Agent Performance:**
Agent invocation rate, p50/p95/p99 latency per agent, error rate, RAG retrieval latency, LLM token consumption (local usage tracking only).

Grafana queries both Prometheus (pipeline metrics) and PostgreSQL (security intelligence) via their respective built-in data source plugins. No custom code is required for the PostgreSQL panels.

---

## 12. Non-Functional Requirements

### 12.1 Performance Targets

| Requirement | Local (Ollama) | Production (Claude) |
|-------------|---------------|---------------------|
| CVE to triaged alert (CRITICAL) | Under 30 minutes | Under 10 minutes |
| Flink throughput (steady state) | 1,000+ events/sec | 10,000+ events/sec |
| Flink throughput (load test) | 5,000+ events/sec | — |
| Triage agent completion | Under 3 minutes | Under 45 seconds |
| MCP tool call latency (p99) | Under 2 seconds | Under 500ms |
| PR Risk Agent completion | Under 2 minutes | Under 30 seconds |

### 12.2 Reliability

- Exactly-once processing via Kafka transactions and Flink checkpointing to MinIO
- Agent idempotency: deduplicated on `(cve_id, service_id, matched_version)`
- Flink checkpoint interval: 60 seconds
- RocksDB state backend persists across Flink restarts
- Agent retry logic with exponential backoff on LLM timeouts

### 12.3 Security

- GitHub Events API requests authenticated with personal access token
- Synthetic generator webhook endpoint validates requests before processing
- All secrets passed via environment variables — never hardcoded or committed
- MinIO credentials changed from defaults before any network exposure
- Ollama runs locally — vulnerability data never leaves the machine during triage

---

## 13. Repository Structure

```
appsec-intelligence/
├── ingestion/                         # Go ingestion services
│   ├── nvd-poller/
│   │   ├── main.go
│   │   ├── client.go
│   │   ├── normaliser.go
│   │   └── cursor.go
│   ├── osv-poller/
│   │   ├── main.go
│   │   ├── client.go
│   │   └── bulk_loader.go
│   ├── github-events-poller/
│   │   ├── main.go
│   │   ├── poller.go
│   │   └── parser.go
│   ├── archive-replayer/
│   │   ├── main.go
│   │   ├── downloader.go
│   │   ├── filter.go
│   │   └── replayer.go
│   └── shared/
│       ├── kafka/
│       ├── schemas/
│       └── metrics/
│
├── stream-processing/                 # PyFlink topology
│   ├── topology.py
│   ├── operators/
│   │   ├── normaliser.py
│   │   ├── deduplicator.py
│   │   ├── manifest_parser.py
│   │   ├── dependency_graph.py
│   │   ├── cve_join.py
│   │   ├── transitive_resolver.py
│   │   ├── blast_radius_scorer.py
│   │   └── router.py
│   ├── schemas/
│   │   ├── vulnerability_event.py
│   │   ├── dependency_change_event.py
│   │   ├── vulnerability_match_event.py
│   │   └── service_dependency_graph.py
│   └── tests/
│
├── agents/                            # Python AI agent layer
│   ├── llm_provider.py               # LLM abstraction (Ollama / Claude)
│   ├── triage/
│   │   ├── agent.py
│   │   ├── nodes.py
│   │   ├── prompts.py
│   │   └── consumer.py
│   ├── pr_risk/
│   │   ├── agent.py
│   │   ├── nodes.py
│   │   ├── prompts.py
│   │   └── consumer.py
│   ├── posture/
│   │   ├── agent.py
│   │   ├── nodes.py
│   │   ├── prompts.py
│   │   └── scheduler.py
│   ├── rag/
│   │   ├── indexer.py
│   │   ├── retriever.py
│   │   └── corpus_builder.py
│   ├── tools/
│   │   ├── github.py
│   │   ├── osv.py
│   │   ├── deps_dev.py
│   │   ├── qdrant.py
│   │   └── service_registry.py
│   └── schemas/
│       ├── triage_report.py
│       ├── pr_risk_verdict.py
│       └── posture_report.py
│
├── mcp-server/
│   ├── server.py
│   ├── tools/
│   │   ├── vulnerability.py
│   │   ├── search.py
│   │   ├── remediation.py
│   │   ├── compliance.py
│   │   └── posture.py
│   └── cache.py
│
├── scripts/
│   ├── synthetic-generator/           # Python — demo scenario container
│   │   ├── Dockerfile
│   │   ├── main.py
│   │   ├── registry.py
│   │   ├── hum.py
│   │   ├── scenarios.py
│   │   └── requirements.txt
│   └── corpus-builder/
│       └── build_corpus.py
│
├── infrastructure/
│   ├── docker-compose.yml
│   ├── sql/
│   │   └── schema.sql
│   ├── prometheus.yml
│   ├── grafana/
│   │   └── dashboards/
│   └── flink-conf.yaml               # MinIO S3 config for Flink checkpoints
│
├── docs/
│   ├── PRD.md                        # This document
│   └── architecture/
│
├── .env.example
├── Makefile
└── README.md
```

---

## 14. Development Phases

| Phase | Name | Scope | Outcome |
|-------|------|-------|---------|
| 1 | Foundation | Docker Compose stack (all services), NVD + OSV pollers, PostgreSQL schema, Flink normalisation + deduplication | Services running locally, CVEs flowing into Kafka |
| 2 | Core Pipeline | GitHub Events API poller, dependency graph operator, CVE join, blast radius scorer, router | End-to-end: CVE published → match event emitted to tier topics |
| 3 | Data Volume | Archive replayer (seed mode), synthetic generator (hum + scenarios), service registry seeded | Flink graph populated, demo scenarios firing reliably |
| 4 | Agent Layer | Qdrant setup, corpus indexing with Ollama embeddings, Triage Agent (LangGraph + Ollama), RAG retrieval, TriageReport output | Full pipeline: CVE match → triage report → PostgreSQL |
| 5 | Extended Agents | PR Risk Agent + GitHub status checks, Posture Agent + compliance mapping, Iceberg audit store on MinIO | All three agents operational, Slack bot integrated |
| 6 | MCP + Delivery | MCP server (9 tools), VS Code + Cline configuration, Grafana dashboards | Natural language queries against live security data from VS Code |
| 7 | Load Test | Archive replayer in load test mode, Prometheus metrics validated, Grafana throughput dashboards | Demonstrable Flink throughput at 5,000+ events/second |
| 8 | Production Path | Swap `LLM_PROVIDER=anthropic`, MinIO → AWS S3 configuration, document production deployment path | Configuration-only migration to cloud validated |

---

## 15. Event Schemas

> Feed this section to an LLM to generate Pydantic models, Go structs, or Avro schemas.

### VulnerabilityEvent

```python
@dataclass
class VulnerabilityEvent:
    event_id:               str
    cve_id:                 str
    source:                 str          # nvd | osv
    published_at:           datetime
    ingested_at:            datetime
    cvss_score:             float
    severity_tier:          str          # CRITICAL | HIGH | MEDIUM | LOW
    cwe_id:                 str | None
    description:            str
    affected_package:       str
    ecosystem:              str          # pypi | npm | maven | go | cargo | rubygems
    affected_version_range: str
    safe_version:           str | None
    affected_versions:      list[str]    # explicit list from OSV, empty for NVD-only CVEs
```

### DependencyChangeEvent

```python
@dataclass
class DependencyChangeEvent:
    event_id:      str
    source:        str          # github_events_api | gh_archive | synthetic
    repo:          str          # e.g. "psf/requests"
    service_id:    str          # derived from repo name or service registry lookup
    pr_number:     int
    author:        str          # e.g. "dependabot[bot]"
    ecosystem:     str
    manifest_file: str
    added:         list[DependencyPin]
    removed:       list[DependencyPin]
    updated:       list[DependencyUpdate]
    occurred_at:   datetime     # PR merged_at timestamp
    ingested_at:   datetime

@dataclass
class DependencyPin:
    package: str
    version: str

@dataclass
class DependencyUpdate:
    package:      str
    from_version: str
    to_version:   str
```

### VulnerabilityMatchEvent

```python
@dataclass
class VulnerabilityMatchEvent:
    match_id:         str
    cve_id:           str
    service_id:       str
    ecosystem:        str
    matched_package:  str
    matched_version:  str
    cvss_score:       float
    severity_tier:    str
    blast_radius_tier: str
    is_transitive:    bool
    transitive_path:  list[str] | None
    service_metadata: ServiceMetadata
    sla_deadline:     datetime
    detected_at:      datetime
```

### NVD API Raw Response — Key Fields

```json
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2024-35195",
      "published": "2024-05-20T09:15:00.000",
      "descriptions": [{"lang": "en", "value": "..."}],
      "metrics": {
        "cvssMetricV31": [{
          "cvssData": {
            "baseScore": 5.9,
            "baseSeverity": "MEDIUM",
            "attackVector": "NETWORK"
          }
        }]
      },
      "weaknesses": [{"description": [{"value": "CWE-295"}]}],
      "configurations": [{
        "nodes": [{
          "cpeMatch": [{
            "vulnerable": true,
            "criteria": "cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.32.0"
          }]
        }]
      }]
    }
  }]
}
```

### OSV API Raw Response — Key Fields

```json
{
  "vulns": [{
    "id": "GHSA-9wx4-h78v-vm56",
    "aliases": ["CVE-2024-35195"],
    "modified": "2024-05-21T00:00:00Z",
    "affected": [{
      "package": {
        "name": "requests",
        "ecosystem": "PyPI"
      },
      "ranges": [{
        "type": "ECOSYSTEM",
        "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]
      }],
      "versions": ["2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.30.0", "2.31.0"]
    }]
  }]
}
```

### GitHub Archive Raw Event — Key Fields

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
      "head": {"ref": "dependabot/pip/urllib3-2.0.7"},
      "changed_files": 1
    }
  },
  "created_at": "2024-02-15T11:45:23Z"
}
```

Note: Archive events do not include file diffs. Package name and version are extracted from `head.ref` (branch name) using Dependabot naming patterns, with PR title regex as fallback.

---

## 16. Cybersecurity Standards Alignment

This section documents alignment with current industry cybersecurity frameworks. It validates that the project addresses real-world security engineering problems and supports compliance mapping in the posture agent.

### 16.1 OWASP Top 10:2025

The 2025 update to the OWASP Top 10 elevates software supply chain failures as a top-tier concern, directly addressed by this platform's real-time dependency monitoring capability.

| Category | Platform Relevance | How Addressed |
|----------|-------------------|--------------| 
| A03 — Software Supply Chain Failures | Direct | Core function: monitors every dependency change and matches against known CVEs in real time |
| A06 — Vulnerable and Outdated Components | Direct | Continuous CVE × dependency graph join across all services |
| A09 — Security Logging and Monitoring Failures | Direct | Immutable Iceberg audit log, Prometheus metrics, continuous detection coverage |
| A01 — Broken Access Control | Indirect | Triage agent identifies CVEs classified under CWE-284, CWE-285, CWE-862 |
| A02 — Cryptographic Failures | Indirect | Blast radius scorer flags PII-handling and payment services for crypto-related CVEs |

### 16.2 NIST Cybersecurity Framework (CSF 2.0)

| CSF Function | Platform Capability | Implementation |
|-------------|-------------------|----------------|
| Identify | Software asset inventory | Flink dependency graph maintains live SBOM per service |
| Identify | Risk assessment | Blast radius scorer quantifies risk per CVE × service match |
| Protect | Supply chain risk management | PR Risk Agent prevents vulnerable dependencies entering the codebase |
| Detect | Continuous vulnerability monitoring | NVD + OSV pollers with real-time Flink detection |
| Respond | Incident response automation | Triage agent generates response runbook for every critical alert |
| Respond | Communications | Slack bot delivers team-routed alerts with assigned responder |
| Recover | Post-incident documentation | Posture agent generates postmortem data; Iceberg stores immutable response timeline |

### 16.3 NIST SP 800-218 — Secure Software Development Framework (SSDF)

| SSDF Practice | Platform Alignment |
|--------------|-------------------|
| PW.4 — Reuse existing, well-secured software | PR Risk Agent assesses dependency maintenance health and historical CVE record |
| PW.7 — Review and analyse human-readable code | Triage agent fetches and analyses source files for exploitability confirmation |
| RV.1 — Identify and confirm vulnerabilities | NVD + OSV ingestion with exact version range matching minimises false positives |
| RV.2 — Assess, prioritise, and remediate | Blast radius scoring and SLA assignment automate prioritisation |
| RV.3 — Analyse vulnerability root causes | Triage agent provides code-level root cause analysis with cited evidence |

### 16.4 CIS Controls v8

| Control | Platform Alignment |
|--------|-------------------|
| CIS 2 — Inventory and Control of Software Assets | Flink dependency graph provides continuous software asset inventory per service |
| CIS 7 — Continuous Vulnerability Management | Core platform function with automated triage |
| CIS 16 — Application Software Security | PR Risk Agent enforces secure dependency management at PR time |
| CIS 17 — Incident Response Management | Triage reports, SLA assignment, and Iceberg audit log support formal IR workflows |

### 16.5 Compliance Framework Mapping

The posture agent's `regulatory_frameworks` RAG collection should include the following for accurate compliance gap mapping:

| Framework | Relevant Controls |
|-----------|-----------------|
| PCI DSS v4.0 | Requirement 6.3 (vulnerabilities identified and addressed), 12.3.2 (targeted risk analysis) |
| HIPAA | §164.306 Security standards, §164.312 Technical safeguards |
| SOC 2 Type II | CC7.1 (detection and monitoring), CC7.2 (evaluation of security events) |
| ISO 27001:2022 | A.12.6 (management of technical vulnerabilities) |
| NIST CSF 2.0 | DE.CM-8 (vulnerability scans performed), RS.AN-5 (vulnerability reporting processes) |

### 16.6 Scope Boundaries

This platform addresses the detection and triage layer of application security. The following are explicitly out of scope and require complementary tooling in a complete AppSec programme:

| Out of Scope | Appropriate Tooling |
|-------------|---------------------|
| Static code analysis (SAST) | Semgrep, CodeQL, SonarQube |
| Dynamic testing (DAST) | OWASP ZAP, Burp Suite |
| Container image scanning | Trivy, Grype |
| Secrets detection | Trufflehog, gitleaks |
| Infrastructure misconfiguration | Checkov, tfsec |

---

## 17. Downstream Application Opportunities

The platform produces several durable outputs — a live dependency graph, a structured triage report store, a compliance-mapped posture report, an MCP server with 9 tools, and a Qdrant RAG knowledge base — that can serve as the foundation for additional standalone applications. Each item below is a self-contained project buildable after the core platform is complete.

### App 1: Security Chat Assistant

**What it is:** A standalone web-based chat interface wired to the MCP server and Qdrant collections. Users query live security intelligence in natural language. Unlike the VS Code + Cline integration, this is a purpose-built UI accessible to any team member — including non-developers such as security managers and compliance staff.

**Example interactions:**
```
"Which teams have the most overdue critical vulnerabilities?"
"Write a remediation plan for the payments team's open critical findings"
"What would exploiting CVE-2025-29907 look like in checkout-api?"
"Generate a compliance summary for our upcoming SOC 2 audit"
```

**Built on:** MCP server + Ollama + React frontend + FastAPI backend. No new infrastructure.
**Effort:** 2–3 days.

---

### App 2: GitHub Actions PR Security Gate

**What it is:** A GitHub Actions workflow that calls the PR Risk Agent via a thin HTTP wrapper every time a pull request touches a dependency file. If the agent returns a BLOCK verdict, the workflow fails the status check and prevents the merge.

**Built on:** FastAPI wrapper around the existing PR Risk Agent (~50 lines) + GitHub Actions YAML configuration.
**Effort:** 1–2 days.
**Demo value:** Opening a PR that adds a known-vulnerable package and watching GitHub block the merge is one of the most compelling live demonstrations the platform can produce.

---

### App 3: Automated SBOM Generator

**What it is:** A tool that exports the Flink dependency graph state as a standards-compliant Software Bill of Materials on demand or on a daily schedule. The SBOM generation is a by-product of the stream processing work already done — the graph already exists.

**Output formats:**
- CycloneDX 1.5 JSON (OWASP-maintained standard, most widely accepted)
- SPDX 2.3 JSON (Linux Foundation standard, required by some US government frameworks)

**Stored:** MinIO bucket `appsec-sboms/{service_id}/{date}.cdx.json`

**Built on:** Python + `cyclonedx-python-lib` + `spdx-tools` + PostgreSQL dep snapshot query + MinIO.
**Effort:** 2–3 days.
**Business context:** SBOM requirements are growing under US Executive Order 14028 and the EU Cyber Resilience Act. Demonstrating automated SBOM generation as a streaming pipeline by-product is a strong portfolio talking point.

---

### App 4: Grafana Security Intelligence Dashboard (Extension)

**What it is:** An extended Grafana dashboard layer that goes beyond pipeline metrics to show actual security intelligence — vulnerability trends, team scorecards, SLA compliance rates, and blast radius heatmaps. Grafana can query PostgreSQL directly via its built-in data source plugin, so the implementation is primarily SQL queries in Grafana panels rather than custom application code.

**Key panels:**
- Open vulnerabilities by severity tier over time
- MTTD and MTTR rolling 30-day trends
- SLA compliance rate by team
- Service blast radius heatmap
- CVE match rate (how often new CVEs match the dependency graph)

**Built on:** Grafana (already running) + PostgreSQL data source. Minimal new code.
**Effort:** 1 day for a polished set of 8–10 panels.

---

### App 5: Slack Security Bot

**What it is:** A Kafka consumer that watches `vuln.triaged` and posts formatted alerts to the correct Slack channel based on which team owns the affected service. Uses Slack Block Kit for structured, actionable notifications.

**Message format:**
```
CRITICAL — CVE-2024-35195 in checkout-api
Package: requests==2.28.0
Fix: pip install requests==2.32.1
Exploitability: CONFIRMED (auth/middleware.py:47)
SLA: 4 hours — due by 18:00 today
Assigned: @sarah
[View Full Report]  [Mark Resolved]  [Snooze 24h]
```

**Built on:** Python + `slack-bolt` SDK + Kafka consumer + PostgreSQL for team routing config.
**Effort:** 1–2 days.

---

### App 6: Vulnerability Remediation Tracker

**What it is:** A lightweight purpose-built web application for tracking the remediation lifecycle of open vulnerabilities. Acts as a security-scoped alternative to creating Jira tickets manually — cards are auto-populated from triage reports and auto-closed when the fix is merged.

**Kanban columns:** Detected → Assigned → In Progress → PR Raised → Resolved

**Key differentiator:** Each card contains the full triage context — exploitability evidence, exact fix command, compliance impact, SLA countdown — so engineers do not need to research the fix themselves. Tickets auto-close when a PR merging the safe version is detected via the GitHub Events API poller.

**Built on:** React + FastAPI + PostgreSQL (`vulnerability_matches` status) + GitHub event detection.
**Effort:** 3–4 days for a functional MVP.

---

### App 7: Executive Security Posture Report (PDF)

**What it is:** A scheduled job that generates a board-ready PDF security report weekly, pulling from the posture agent's output. Targeted at CISOs and engineering leadership — non-technical stakeholders who need a document they can review offline.

**Contents:** Executive summary (LLM-generated plain English), vulnerability trend charts, team security scorecards, SLA compliance rate, top five critical open items, compliance gap summary, recommended actions for the next sprint.

**Built on:** Python + `reportlab` or `weasyprint` + PostgreSQL + Matplotlib charts. Stored in MinIO. Delivered via email or Slack.
**Effort:** 2–3 days.

---

### App 8: AppSec Training Simulator

**What it is:** An interactive quiz application that uses real CVE data from the pipeline to generate developer security training scenarios. A developer is shown a real code snippet alongside a real CVE description and asked to identify whether the code is vulnerable, where, and how to fix it.

**Round structure:**
1. Present: real CVE description (from Qdrant `cve_descriptions`)
2. Present: a code snippet (from the RAG corpus or synthetic)
3. Ask: "Is this code vulnerable?"
4. If yes: "Click the vulnerable line"
5. Reveal: triage agent's analysis of this CVE + code pattern as the explanation

The triage agent's code analysis capability — built for production use — is repurposed here to evaluate answers and generate explanations. Same agent, different application context.

**Built on:** React + FastAPI + Qdrant + Ollama + PostgreSQL for score tracking.
**Effort:** 3–4 days for a functional prototype.

---

### App 9: Multi-Tenant SaaS Platform

**What it is:** A productised version of the platform offered as a hosted service. Each customer has an isolated namespace in Kafka, Flink, and PostgreSQL with their own GitHub repositories connected and their own security intelligence dashboard. The shared infrastructure — CVE ingestion, NVD/OSV polling, Flink cluster — runs once for all tenants.

**Built on:** Full platform with a multi-tenancy layer added via Kafka topic prefixing, PostgreSQL row-level security, and per-tenant Flink job configuration.
**Effort:** 2–4 weeks for a production-grade multi-tenant implementation.
**Business model:** SaaS subscription for engineering teams that cannot build this in-house.

---

### Summary

| Application | Primary User | New Infrastructure | Effort | Standout Demo Moment |
|-------------|-------------|-------------------|--------|---------------------|
| Security Chat Assistant | Security team, managers | None | 2–3 days | Ask it anything in natural language |
| GitHub PR Security Gate | Developers | Thin HTTP wrapper | 1–2 days | Block a vulnerable merge live |
| SBOM Generator | Compliance | None | 2–3 days | Export CycloneDX in seconds |
| Grafana Intelligence Dashboard | Everyone | None (already running) | 1 day | Live security numbers on screen |
| Slack Security Bot | All teams | Slack app | 1–2 days | Alert fires during the demo |
| Remediation Tracker | Security + Dev | None | 3–4 days | Auto-closes when fix is merged |
| Executive PDF Report | CISO / VP Eng | None | 2–3 days | Hand a stakeholder a real document |
| AppSec Training Simulator | Developers | None | 3–4 days | Scored against a real CVE |
| Multi-Tenant SaaS | External customers | Full platform | 2–4 weeks | Fully productised offering |

**Recommended build order after core platform:**
1. Grafana dashboard (1 day, immediate visual payoff, zero new code)
2. Slack bot (makes the pipeline feel live during demos)
3. GitHub PR Gate (closes the loop from detection back to prevention)
4. Security Chat Assistant (most impressive for non-technical audiences)
5. Remaining apps in any order

---

## 18. Glossary

| Term | Definition |
|------|-----------|
| CVE | Common Vulnerabilities and Exposures — standardised identifier for publicly disclosed software vulnerabilities |
| CVSS | Common Vulnerability Scoring System — severity score on a 0–10 scale |
| CWE | Common Weakness Enumeration — classification of software weakness types |
| CPE | Common Platform Enumeration — NVD's identifier for software products (less useful than OSV for package matching) |
| Blast Radius | Scope of potential impact if a vulnerability is exploited, weighted by service criticality and compliance scope |
| MTTD | Mean Time to Detect — elapsed time from vulnerability disclosure to identification in your environment |
| MTTR | Mean Time to Remediate — elapsed time from detection to successful remediation |
| PyFlink | Python API for Apache Flink enabling stateful, fault-tolerant stream processing |
| RAG | Retrieval-Augmented Generation — grounds LLM reasoning in retrieved documents rather than model memory alone |
| MCP | Model Context Protocol — open protocol enabling AI assistants to invoke structured tools |
| LangGraph | Python library for building multi-step stateful AI agent workflows as directed graphs |
| Exactly-Once | Processing guarantee ensuring each event is processed exactly once despite failures or retries |
| Transitive Dependency | An indirect dependency — a package your code depends on because one of its direct dependencies requires it |
| SBOM | Software Bill of Materials — structured inventory of all software components and their versions |
| SLA | Service Level Agreement — maximum permitted time between vulnerability detection and remediation |
| MinIO | Open-source S3-compatible object storage server, runs locally via Docker with zero cloud dependency |
| Ollama | Open-source local LLM inference server — runs quantized models on consumer hardware using Apple Metal or CUDA |
| Redpanda | Kafka-compatible message broker with lower resource footprint, suitable for local development |
| Iceberg | Apache Iceberg — open table format with ACID guarantees for large analytic datasets, used here for the immutable audit log |
| RocksDB | Embedded key-value store used as Flink's state backend for large stateful operator graphs |
| Cline | Open-source VS Code extension providing an AI coding assistant with MCP tool integration support |
| OWASP | Open Web Application Security Project — non-profit producing widely adopted application security standards |
| NIST CSF | NIST Cybersecurity Framework 2.0 — five-function risk management structure: Identify, Protect, Detect, Respond, Recover |
| SSDF | Secure Software Development Framework (NIST SP 800-218) — DevSecOps integration practices for the software development lifecycle |
| CIS Controls | Center for Internet Security Controls — prioritised set of defensive actions for organisations of any size |
| Dependabot | GitHub's automated dependency update bot — opens PRs to bump vulnerable or outdated packages |
| Renovate | Open-source alternative to Dependabot — supports more ecosystems and configuration options |

---

*Real-Time AppSec Intelligence Platform — PRD v2.0.0*
*Local-first: MinIO + Ollama (qwen2.5-coder:7b) on Docker Compose*
*Production path: AWS S3 + Anthropic Claude Sonnet — configuration changes only*
