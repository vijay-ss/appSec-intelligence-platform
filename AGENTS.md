# AGENTS.md — AppSec Intelligence Platform

Multi-language monorepo for real-time AppSec intelligence:
- **Go** — Ingestion layer (NVD, OSV, GitHub Events pollers, archive-replayer)
- **Python** — Stream processing (Flink), AI triage agents, MCP server
- **Infrastructure** — Docker Compose with Redpanda, PostgreSQL, Redis, MinIO, Qdrant, Ollama

## Build, Test & Lint Commands

### Docker-Based (via Makefile)
```bash
make build          # Build all Docker images
make up             # Start full stack
make down           # Stop containers (data preserved)
make clean          # Stop AND delete volumes (destructive)
make infra-up       # Infrastructure only (Kafka, Postgres, MinIO, Qdrant, Redis)
make pollers-up     # Add Go ingestion pollers
make flink-up       # Add Flink + stream processing topology
make agents-up      # Add Ollama + triage agent + MCP server
make rebuild s=<svc>  # Rebuild and restart one service
make shell s=<svc>    # Open shell inside container
make logs s=<svc>     # Tail logs from one service
make ps               # Show running containers
make scenario SCENARIO=<name>  # Fire demo scenario (default: critical_rce)
make corpus           # Index OSV data into Qdrant
```

### Running a Single Test
```bash
# Python/Flink tests
docker compose run --rm --no-deps -e PYTHONPATH=/opt/flink/userjobs \
  flink-jobmanager python -m pytest /opt/flink/userjobs/tests/ -v -k test_function_name

# Go tests (inside container)
docker run --rm -v $(PWD)/ingestion:/build -w /build golang:1.22-bookworm \
  go test ./... -run TestName -v

# Go tests (direct, no Docker)
cd ingestion && go test ./... -v && go build ./... && go vet ./...
```

---

## Go Code Conventions

### Naming Conventions
- **Types/Structs/Exported Functions**: `PascalCase` (e.g., `VulnerabilityEvent`)
- **Unexported functions**: `camelCase`
- **Variables/Parameters**: `camelCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Package/File names**: `lowercase` or `snake_case.go`

### Imports (ordered groups)
```go
import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/confluentinc/confluent-kafka-go/v2/kafka"
    "github.com/google/uuid"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"

    sharedkafka "github.com/vijay-ss/appsec-intelligence/ingestion/shared/kafka"
)
```

### Struct Tags & Error Handling
```go
type VulnerabilityEvent struct {
    EventID    string    `json:"event_id"`
    CVEID      string    `json:"cve_id"`
    CWEID      string    `json:"cwe_id,omitempty"`  // omitempty for optional
}

// Fatal — program cannot continue
if err != nil {
    log.Fatal().Err(err).Msg("failed to create kafka producer")
}

// Recoverable — log and continue
if err != nil {
    log.Error().Err(err).Str("cve_id", event.CVEID).Msg("publish failed")
    continue
}

// Return for caller to handle
if err != nil {
    return nil, fmt.Errorf("parse cursor: %w", err)
}
```

### Logging (zerolog)
```go
log.Info().Str("brokers", brokers).Int("poll_secs", pollSecs).Msg("nvd poller starting")
log.Error().Err(err).Str("cve_id", event.CVEID).Msg("publish failed")
```

### Comments
Comment all exported functions, types, and constants:
```go
// SeverityFromCVSS maps a CVSS score to a severity tier.
func SeverityFromCVSS(score float64) string { ... }
```

---

## Python Code Conventions (PyFlink, agents, MCP server)

### Naming Conventions
- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **File names**: `snake_case.py`
- **Type hints**: Required throughout

### Import Ordering
```python
# Standard library
import argparse
import json
import uuid
from datetime import datetime

# Third-party
import psycopg2
from confluent_kafka import Producer

# Local
from registry import SERVICES
```

### Error Handling
```python
try:
    conn = psycopg2.connect(POSTGRES_URL)
except Exception as e:
    print(f"[error] failed to connect: {e}")
    raise
```

---

## Service Endpoints
| Service | URL |
|---------|-----|
| Redpanda Console | http://localhost:8083 |
| Flink Dashboard | http://localhost:8081 |
| MinIO Console | http://localhost:9001 (minioadmin/minioadmin) |
| Grafana | http://localhost:3000 (admin/admin) |
| Scenario Trigger | http://localhost:8090 |

## Environment Variables
Copy `.env.example` to `.env`:
- `KAFKA_BROKERS` — Kafka broker address
- `POSTGRES_URL` — PostgreSQL connection string
- `NVD_API_KEY` — NIST NVD API key (optional)
- `HUM_RATE` — Synthetic events/sec (default: 2.0)
- `REPLAYER_MODE` — seed|loadtest|continuous (default: continuous)

## Documentation
- **PRD**: `docs/appsec-intelligence-prd-v2.0.md`
- **Architecture**: `docs/architecture/ARCHITECTURE.md`
- **Go Services**: `ingestion/README.md`
- **Infrastructure**: `infrastructure/README.md`

## Available Agents

Invoke agents using `@agent-name`:

| Agent | Invoke | Purpose |
|-------|--------|---------|
| `@code-reviewer` | `@code-reviewer` | Logic, intent, edge cases (after commits, before PRs) |
| `@security-engineer` | `@security-engineer` | Secrets, CVEs, vulnerabilities |
| `@debugger` | `@debugger` | Debug Python, PyFlink, Go, and Docker errors |

### Code Reviewer (`@code-reviewer`)
Reviews code changes for logic correctness, intent alignment, and edge case handling.

**Focus areas:**
- Go: Goroutine leaks, unhandled errors, race conditions, data loss
- Python: Mutable defaults, silent exceptions, missing type hints
- Dockerfile: Root user, missing HEALTHCHECK, secret leaks

### Security Engineer (`@security-engineer`)
Scans for security issues including hardcoded secrets, code vulnerabilities, and dependency CVEs.

**Scan order:**
1. Git history for committed secrets
2. Working tree for hardcoded credentials
3. Code vulnerability patterns
4. Dependency CVE checks
5. Docker security misconfigurations

### Debugger (`@debugger`)
Debugs runtime errors from Python, PyFlink, Go, and Docker executions.

**Error input:**
- Parse pasted stack traces or terminal output
- Fetch logs from Docker containers via `docker logs`
- Read source files to understand code context

**Focus areas:**
- Python/PyFlink: Traceback parsing, state backend issues, type mismatches, import errors, API version conflicts
- Go: Nil pointer dereference, goroutine leaks, race conditions, import cycles, build errors
- Docker: Exit codes, OOM kills, volume mounts, port conflicts, healthcheck failures

**Allowed commands (read-only, curated subset):**
| Category | Commands |
|----------|----------|
| Docker | `docker ps`, `docker logs <id>`, `docker inspect <id>`, `docker compose ps` |
| Go | `go build ./...`, `go test ./...`, `go vet ./...`, `go list -m all` |
| Python | `python -c <code>`, `python -m pytest`, `pip list` |
| System | `curl` (health checks), `cat` (read files), `ls` |

**Excluded:** Any command that modifies state (`docker kill`, `docker rm`, `go install`, `pip install`, etc.)

**Workflow:**
1. Parse error → identify runtime and source file
2. Read relevant source files for context
3. Propose diagnostic commands (user must confirm each)
4. Run command → analyze output
5. Repeat until root cause is identified (max 3 rounds)

**Output format:**
```
## Error Analysis
<root cause explanation>

## Context
<relevant code snippets>

## Proposed Commands
<command to run>

## Verification
<command to confirm the fix>
```
