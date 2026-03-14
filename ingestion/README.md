# Ingestion Layer

Four independent Go binaries that poll upstream vulnerability and dependency data sources, normalise the responses to canonical schemas, and publish JSON events to Kafka (Redpanda). All four services share a single Go module (`go.mod` at `ingestion/`) and the common producer and schema packages in `ingestion/shared/`.

Each poller is stateless at the application level. Polling position is tracked in Redis so a restarted container picks up exactly where it left off.

---

## Running in Docker

All four pollers run as Docker containers. You do not need Go installed.

### Start all pollers

```bash
# From the repo root — starts infrastructure then pollers
make infra-up
make pollers-up
```

Or start individual pollers:

```bash
docker compose -f infrastructure/docker-compose.yml up -d nvd-poller
docker compose -f infrastructure/docker-compose.yml up -d osv-poller
docker compose -f infrastructure/docker-compose.yml up -d github-events-poller
```

The archive replayer is disabled by default (it's in the `replay` Docker Compose profile). Start it explicitly:

```bash
docker compose -f infrastructure/docker-compose.yml --profile replay up -d archive-replayer
```

### Watch the output

```bash
# Via make
make logs s=nvd-poller
make logs s=osv-poller
make logs s=github-events-poller

# Directly
docker compose -f infrastructure/docker-compose.yml logs -f nvd-poller
```

You should see JSON log lines like:

```
nvd-poller  | {"service":"nvd-poller","level":"info","event":"fetched nvd page","total_results":2341,"page":0}
nvd-poller  | {"service":"nvd-poller","level":"info","event":"published event","cve_id":"CVE-2024-35195","topic":"vulns.nvd.raw"}
```

### Verify events are arriving in Kafka

Open the Redpanda console at [http://localhost:8080](http://localhost:8080) → **Topics**. You should see messages on:

- `vulns.nvd.raw` — NVD CVE events
- `vulns.osv.raw` — OSV vulnerability events
- `deps.changes` — dependency change events

Or inspect from the command line:

```bash
docker compose -f infrastructure/docker-compose.yml exec redpanda \
  rpk topic consume vulns.nvd.raw --brokers localhost:9092 -n 5
```

### Rebuild after changing Go code

```bash
make rebuild s=nvd-poller
make rebuild s=osv-poller
make rebuild s=github-events-poller

# Or rebuild all four at once
docker compose -f infrastructure/docker-compose.yml build \
  nvd-poller osv-poller github-events-poller archive-replayer
```

Builds use a two-stage Dockerfile: a `golang:1.22-bookworm` stage compiles the binary, and a lean `debian:bookworm-slim` runtime stage holds only the binary and the `librdkafka` shared library (~30MB final image).

### Open a shell inside a running poller

```bash
make shell s=nvd-poller

# Once inside:
env | grep KAFKA    # check env vars
cat /proc/1/cmdline # confirm the right binary is running
```

### Run the archive replayer as a one-shot seed

```bash
# Seed the Flink dep graph from all of 2024 at maximum speed, then exit
docker compose -f infrastructure/docker-compose.yml --profile replay run --rm \
  archive-replayer \
  --start-date 2024-01-01 --end-date 2025-01-01 --mode seed --delay-ms 0

# Or via make
make load-test
```

---

## Environment variables

Set these in `.env` at the repo root. Docker Compose reads `.env` automatically and passes matching variables through.

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BROKERS` | `redpanda:9092` | Broker address — `redpanda:9092` inside Docker, `localhost:9092` from host |
| `REDIS_ADDR` | `redis:6379` | Redis address — `redis:6379` inside Docker, `localhost:6379` from host |
| `NVD_API_KEY` | *(empty)* | Optional — free key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key). Raises rate limit from 5 to 50 req/30s |
| `GITHUB_TOKEN` | *(empty)* | Optional — free PAT from [github.com/settings/tokens](https://github.com/settings/tokens). Raises rate limit from 60 to 5,000 req/hr |
| `NVD_POLL_INTERVAL_SECONDS` | `300` | How often to poll NVD (5 minutes) |
| `OSV_POLL_INTERVAL_SECONDS` | `600` | How often to poll OSV incrementally (10 minutes) |
| `GITHUB_POLL_INTERVAL_SECONDS` | `60` | How often to poll each GitHub repo |

```bash
# .env (optional — pollers work without these, just with lower rate limits)
NVD_API_KEY=your-free-key-here
GITHUB_TOKEN=ghp_yourtoken
```

---

## Running unit tests

```bash
# No Go installation needed — runs inside a temporary Go container
make test

# Equivalent manual command
docker run --rm \
  -v $(pwd)/ingestion:/build \
  -w /build \
  golang:1.22-bookworm \
  go test ./...
```

---

## Running without Docker (optional)

If you prefer to run a poller directly on your machine for rapid iteration, start the infrastructure dependencies in Docker and connect from your local process:

```bash
# Start just the services the pollers need
docker compose -f infrastructure/docker-compose.yml up -d redpanda redis

# Run any poller with go run — note localhost addresses
cd ingestion
KAFKA_BROKERS=localhost:9092 REDIS_ADDR=localhost:6379 go run nvd-poller/main.go
KAFKA_BROKERS=localhost:9092 REDIS_ADDR=localhost:6379 go run osv-poller/main.go
KAFKA_BROKERS=localhost:9092 REDIS_ADDR=localhost:6379 go run github-events-poller/main.go

# Archive replayer with explicit date range
KAFKA_BROKERS=localhost:9092 go run archive-replayer/main.go \
  --start-date 2024-01-01 --end-date 2024-01-02 --mode seed
```

The broker address changes from `redpanda:9092` (Docker network hostname) to `localhost:9092` (exposed port on your machine).

---

## Services

### `nvd-poller`

**Kafka topic:** `vulns.nvd.raw`

Polls the [NVD CVE 2.0 REST API](https://nvd.nist.gov/developers/vulnerabilities) on a configurable interval (default 5 minutes). Uses a Redis key (`nvd:cursor:last_pub_date`) as a cursor. On each poll it fetches CVEs published between the last cursor value and now, then advances the cursor. On first run it looks back 24 hours.

NVD provides two fields the pipeline uses: **CVSS base score** and **CWE classification**. It does not provide usable package-level version data (it uses CPE strings, which are not joinable against package manager names). Package version ranges come from OSV.

**What it emits:**
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

Note `affected_package` and `affected_version_range` are intentionally empty — the Flink CVE join uses OSV events for version matching.

---

### `osv-poller`

**Kafka topic:** `vulns.osv.raw`

[OSV.dev](https://osv.dev) is the primary source for package-level version data. It maps CVE IDs to exact package names and affected version lists across six ecosystems: PyPI, npm, Maven, Go, crates.io, and RubyGems.

**First run — bulk load:** Downloads the complete OSV corpus from Google Cloud Storage (`https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`). All six ecosystems are downloaded concurrently. The highest `modified` timestamp seen across all records is written to Redis as the incremental cursor, then a flag (`osv:bulk_loaded`) is set so subsequent restarts skip the bulk load entirely.

**Subsequent runs — incremental:** Every 10 minutes, for each ecosystem:
1. Fetches `modified_id.csv` from GCS — a lightweight (~200KB) index of `(id, modified_time)` pairs sorted newest-first
2. Reads entries until `modified_time <= cursor`, collecting only new IDs
3. Fetches each new record by ID from the OSV REST API (`GET /v1/vulns/{id}`)
4. Publishes to Kafka and advances the cursor

Note: `POST /v1/query` is not used for polling — that endpoint requires a specific package+version and does not support time-based filtering. The `modified_id.csv` index + `GET /v1/vulns/{id}` is the correct OSV pattern for tracking recent changes.

**What it emits:**
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

---

### `github-events-poller`

**Kafka topic:** `deps.changes`

Polls the [GitHub Events API](https://docs.github.com/en/rest/activity/events) every 60 seconds across 15 target repositories. Filters for merged Dependabot and Renovate PRs and extracts package name and version from the branch name and PR title.

**Target repositories:**

| Repo | Ecosystem |
|---|---|
| `psf/requests`, `django/django`, `fastapi/fastapi`, `encode/httpx`, `apache/airflow`, `pydantic/pydantic`, `pallets/flask`, `home-assistant/core` | pypi |
| `vercel/next.js`, `microsoft/vscode`, `expressjs/express`, `nodejs/node`, `renovatebot/renovate` | npm |
| `kubernetes/kubernetes`, `hashicorp/terraform` | go |

**What it emits:**
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
  "updated": [
    { "package": "urllib3", "from_version": "1.26.14", "to_version": "2.0.7" }
  ],
  "occurred_at": "2024-02-15T11:45:22Z",
  "ingested_at": "2024-02-15T11:45:31Z"
}
```

---

### `archive-replayer`

**Kafka topic:** `deps.changes`

Downloads and replays hourly `.json.gz` files from [gharchive.org](https://gharchive.org). Filters down to merged Dependabot/Renovate PRs from 2024 onwards.

**Three operating modes:**

| Mode | Behaviour | Use case |
|---|---|---|
| `seed` | Replays the date range then exits | Initial data load — run once before starting the full pipeline |
| `loadtest` | Replays at maximum speed (no delay) | Throughput demonstration |
| `continuous` | Replays one day at a time on a loop | Background replay for demos |

This service is in the `replay` Docker Compose profile and is off by default. The live pollers (nvd, osv, github-events) are the normal data source. Use the replayer when you need historical data or high-volume load testing.

---

### `shared/`

Internal packages used by all four pollers. Not a deployable service.

**`shared/kafka/producer.go`** — wraps `confluent-kafka-go` with idempotent delivery, `acks=all`, snappy compression, and a background goroutine that logs delivery failures.

**`shared/schemas/events.go`** — canonical Go structs for `VulnerabilityEvent` and `DependencyChangeEvent`, plus helper functions `SeverityFromCVSS()`, `EcosystemFromBranch()`, and `ManifestForEcosystem()`.
