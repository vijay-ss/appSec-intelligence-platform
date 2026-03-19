# AGENTS.md — AppSec Intelligence Platform

This file provides guidance for AI coding agents working in this repository.

## Project Overview

Multi-language monorepo for a real-time AppSec intelligence platform:
- **Go** — Ingestion layer (NVD, OSV, GitHub Events pollers, archive-replayer)
- **Python** — Stream processing (Flink), AI triage agents, MCP server
- **Infrastructure** — Docker Compose with Redpanda, PostgreSQL, Redis, MinIO, Qdrant, Ollama

## Build, Test & Lint Commands

### Docker-Based Commands (via Makefile)
```bash
# Build & Run
make build              # Build all Docker images
make up                 # Start full stack
make down               # Stop containers (data preserved)
make clean              # Stop AND delete volumes (destructive)

# Layered startup (build one layer at a time)
make infra-up           # Infrastructure only (Kafka, Postgres, MinIO, Qdrant, Redis)
make pollers-up         # Add Go ingestion pollers
make flink-up           # Add Flink + submit stream processing topology
make agents-up          # Add Ollama + triage agent + MCP server

# Testing
make test               # Run all unit tests (PyFlink + Go in containers)

# Individual services
make rebuild s=<svc>    # Rebuild and restart one service
make shell s=<svc>      # Open shell inside a running container
make logs s=<svc>       # Tail logs from one service
```

### Running a Single Test

**Go tests (run inside container):**
```bash
docker run --rm \
  -v $(PWD)/ingestion:/build \
  -w /build \
  golang:1.22-bookworm \
  go test ./... -run TestFunctionName -v
```

**Python/Flink tests:**
```bash
docker compose run --rm --no-deps \
  -e PYTHONPATH=/opt/flink/userjobs \
  flink-jobmanager \
  python -m pytest /opt/flink/userjobs/tests/ -v -k test_function_name
```

### Direct Go Commands (no Docker)
```bash
cd ingestion
go test ./... -v                    # Run all tests
go test -run TestName -v           # Run single test
go build ./...                      # Build all packages
go vet ./...                        # Lint
```

---

## Go Code Conventions

### Naming Conventions
- **Types & Structs**: `PascalCase` (e.g., `VulnerabilityEvent`, `DependencyChangeEvent`)
- **Functions (exported)**: `PascalCase`
- **Functions (unexported)**: `camelCase`
- **Variables & Parameters**: `camelCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Package names**: `lowercase` or `snake_case` (e.g., `sharedkafka`)
- **File names**: `snake_case.go` (e.g., `github_events_poller`, `producer.go`)

### Imports
Standard library imports first, then third-party, then internal:
```go
import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"

    sharedkafka "github.com/vijay-ss/appsec-intelligence/ingestion/shared/kafka"
    "github.com/vijay-ss/appsec-intelligence/ingestion/shared/schemas"
)
```

### Struct Tags
Use JSON tags for all exported struct fields:
```go
type nvdResponse struct {
    TotalResults    int       `json:"totalResults"`
    Vulnerabilities  []nvdItem `json:"vulnerabilities"`
}
```

### Error Handling
Always handle errors explicitly. Use `zerolog` for logging:
```go
// Fatal errors — program cannot continue
if err != nil {
    log.Fatal().Err(err).Msg("failed to create kafka producer")
}

// Recoverable errors — log and continue/return
if err != nil {
    log.Error().Err(err).Str("cve_id", event.CVEID).Msg("publish failed")
    continue
}

// Return errors for caller to handle
if err != nil {
    return nil, fmt.Errorf("parse cursor: %w", err)
}
```

### Logging (zerolog)
Use structured logging with contextual fields:
```go
log.Info().
    Str("brokers", brokers).
    Int("poll_interval_seconds", pollSecs).
    Bool("api_key_set", apiKey != "").
    Msg("nvd poller starting")

log.Error().
    Err(err).
    Str("cve_id", event.CVEID).
    Msg("publish failed")
```

### Comments
Comment all exported functions, types, and constants:
```go
// SeverityFromCVSS maps a CVSS score to a severity tier.
func SeverityFromCVSS(score float64) string { ... }

// nvdTimeLayout is the NVD API's timestamp format.
const nvdTimeLayout = "2006-01-02T15:04:05.000"
```

---

## Python Code Conventions (for stream-processing, agents, MCP server)

### Naming Conventions
- **Functions & Variables**: `snake_case` (e.g., `get_producer`, `hum_rate`)
- **Classes**: `PascalCase` (e.g., `ScenarioHandler`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `KAFKA_BROKERS`)
- **File names**: `snake_case.py` (e.g., `main.py`, `registry.py`)
- **Type hints**: Use throughout (see PEP 484)

### Import Ordering
```python
# Standard library
import argparse
import json
import os
import uuid
from datetime import datetime

# Third-party
import psycopg2
from confluent_kafka import Producer

# Local
from registry import SERVICES
from scenarios import SCENARIOS
```

### Type Hints
Always use type hints for function signatures:
```python
def get_producer() -> Producer:
    return Producer({"bootstrap.servers": KAFKA_BROKERS})

def hum(producer: Producer) -> None:
    ...
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

## Architecture & Documentation

- **PRD**: `docs/appsec-intelligence-prd-v2.0.md` — Full specification for all components
- **Architecture**: `docs/architecture/ARCHITECTURE.md` — System design and data flow
- **Go Services**: `ingestion/README.md` — Ingestion layer details
- **Infrastructure**: `infrastructure/README.md` — Docker Compose stack
- **Synthetic Generator**: `scripts/synthetic-generator/README.md` — Demo data

---

## Service Endpoints

| Service | URL |
|---------|-----|
| Redpanda Console | http://localhost:8080 |
| Flink Dashboard | http://localhost:8081 |
| MinIO Console | http://localhost:9001 (minioadmin/minioadmin) |
| Grafana | http://localhost:3000 (admin/admin) |
| Scenario Trigger | http://localhost:8090 |

---

## Environment Variables

Copy `.env.example` to `.env` and configure:
- `KAFKA_BROKERS` — Kafka broker address
- `REDIS_ADDR` — Redis address
- `POSTGRES_URL` — PostgreSQL connection string
- `NVD_API_KEY` — NIST NVD API key (optional, improves rate limits)
