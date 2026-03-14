# AppSec Intelligence Platform — Makefile
# Everything runs in Docker. You only need Docker installed on your machine.
# Run `make help` to see all available targets.

.PHONY: help build up down logs clean ps \
        infra-up pollers-up agents-up flink-up \
        flink corpus scenario load-test \
        test rebuild shell

COMPOSE      = docker compose -f infrastructure/docker-compose.yml
SCENARIO    ?= critical_rce

# ── Help ─────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "AppSec Intelligence Platform"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "Everything runs in Docker — no local Python or Go needed."
	@echo ""
	@echo "First time setup"
	@echo "  make build        Build all Docker images (do this first)"
	@echo "  make up           Start everything"
	@echo ""
	@echo "Layered startup (build up one layer at a time)"
	@echo "  make infra-up     Start infrastructure only (Kafka, Postgres, MinIO, etc.)"
	@echo "  make pollers-up   Add the Go ingestion pollers"
	@echo "  make flink-up     Add Flink + submit the stream processing topology"
	@echo "  make agents-up    Add the triage agent and MCP server"
	@echo ""
	@echo "Individual services"
	@echo "  make flink        Rebuild Flink image and resubmit topology"
	@echo "  make corpus       Run the corpus builder (indexes OSV data into Qdrant)"
	@echo ""
	@echo "Observability"
	@echo "  make ps           Show running containers and their status"
	@echo "  make logs         Tail logs from all containers"
	@echo "  make logs s=<svc> Tail logs from one service  e.g. make logs s=triage-agent"
	@echo ""
	@echo "Demo"
	@echo "  make scenario     Fire a demo scenario (default: critical_rce)"
	@echo "                    SCENARIO=mass_exposure make scenario"
	@echo "  make load-test    Replay 2024-01 at full speed using archive-replayer"
	@echo ""
	@echo "Development"
	@echo "  make test         Run unit tests inside containers (no cluster needed)"
	@echo "  make rebuild s=<svc>  Rebuild and restart one service"
	@echo "                    e.g. make rebuild s=triage-agent"
	@echo "  make shell s=<svc>    Open a shell inside a running container"
	@echo "                    e.g. make shell s=triage-agent"
	@echo ""
	@echo "Teardown"
	@echo "  make down         Stop all containers (data is preserved in volumes)"
	@echo "  make clean        Stop all containers AND delete all volumes (destructive)"
	@echo ""
	@echo "Service UIs"
	@echo "  Redpanda Console   http://localhost:8080"
	@echo "  Flink Dashboard    http://localhost:8081"
	@echo "  MinIO Console      http://localhost:9001  (minioadmin / minioadmin)"
	@echo "  Grafana            http://localhost:3000  (admin / admin)"
	@echo "  Scenario trigger   http://localhost:8090"
	@echo ""

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	@echo "Building all images..."
	$(COMPOSE) build
	@echo ""
	@echo "All images built. Run 'make up' to start."

# ── Startup helpers ──────────────────────────────────────────────────────────
# These let you bring up one layer at a time so you can understand what each
# part does before adding the next.

infra-up:
	@echo "Starting infrastructure (Kafka, Postgres, MinIO, Qdrant, Redis, Ollama)..."
	$(COMPOSE) up -d \
	  redpanda minio minio-init postgres qdrant redis \
	  prometheus grafana
	@echo ""
	@echo "Infrastructure ready:"
	@echo "  Redpanda Console  http://localhost:8080"
	@echo "  MinIO Console     http://localhost:9001"
	@echo "  Grafana           http://localhost:3000"

pollers-up:
	@echo "Starting Go ingestion pollers..."
	$(COMPOSE) up -d nvd-poller osv-poller github-events-poller synthetic-generator
	@echo ""
	@echo "Pollers running. Watch events in Redpanda Console: http://localhost:8080"
	@echo "Topics to watch: vulns.nvd.raw  vulns.osv.raw  deps.changes"

flink-up:
	@echo "Building Flink image and starting cluster..."
	$(COMPOSE) build flink-jobmanager
	$(COMPOSE) up -d flink-jobmanager flink-taskmanager
	@echo "Waiting for Flink to be healthy..."
	@until $(COMPOSE) exec -T flink-jobmanager curl -sf http://localhost:8081/overview > /dev/null 2>&1; do \
	  echo "  still waiting..."; sleep 5; \
	done
	@echo "Submitting PyFlink topology..."
	$(COMPOSE) up flink-job-submitter
	@echo ""
	@echo "Flink running. Dashboard: http://localhost:8081"

agents-up:
	@echo "Starting Ollama model pull, triage agent, and MCP server..."
	$(COMPOSE) up -d ollama
	$(COMPOSE) up -d ollama-init
	$(COMPOSE) up -d triage-agent mcp-server
	@echo ""
	@echo "Agents running."
	@echo "MCP server on port 8000 — see mcp-server/README.md for VS Code config."

# ── Full stack ────────────────────────────────────────────────────────────────

up:
	$(COMPOSE) up -d
	@echo ""
	@echo "Full stack starting. This may take several minutes on first run"
	@echo "while Docker builds images and Ollama downloads models."
	@echo ""
	@echo "  Redpanda Console   http://localhost:8080"
	@echo "  Flink Dashboard    http://localhost:8081"
	@echo "  MinIO Console      http://localhost:9001  (minioadmin / minioadmin)"
	@echo "  Grafana            http://localhost:3000  (admin / admin)"
	@echo "  Scenario trigger   http://localhost:8090"

down:
	$(COMPOSE) down

clean:
	@echo "WARNING: this deletes all Docker volumes including PostgreSQL data and Ollama models."
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	$(COMPOSE) down -v

ps:
	$(COMPOSE) ps

logs:
ifdef s
	$(COMPOSE) logs -f $(s)
else
	$(COMPOSE) logs -f
endif

# ── Individual service operations ─────────────────────────────────────────────

flink:
	@echo "Rebuilding Flink image and resubmitting topology..."
	$(COMPOSE) build flink-jobmanager
	$(COMPOSE) up -d flink-jobmanager flink-taskmanager
	$(COMPOSE) restart flink-job-submitter

corpus:
	@echo "Running corpus builder (indexes OSV data into Qdrant)..."
	$(COMPOSE) --profile setup run --rm corpus-builder

rebuild:
ifndef s
	$(error Usage: make rebuild s=<service-name>  e.g. make rebuild s=triage-agent)
endif
	$(COMPOSE) build $(s)
	$(COMPOSE) up -d --force-recreate $(s)

shell:
ifndef s
	$(error Usage: make shell s=<service-name>  e.g. make shell s=triage-agent)
endif
	$(COMPOSE) exec $(s) /bin/bash || $(COMPOSE) exec $(s) /bin/sh

# ── Demo ──────────────────────────────────────────────────────────────────────

scenario:
	curl -s -X POST http://localhost:8090/scenario \
	     -H "Content-Type: application/json" \
	     -d '{"scenario": "$(SCENARIO)"}' | python3 -m json.tool
	@echo ""
	@echo "Scenario '$(SCENARIO)' fired."
	@echo "Watch matches arrive at: http://localhost:8080  (Topics → vuln.matches.critical)"

load-test:
	@echo "Running load test via archive-replayer at full speed..."
	$(COMPOSE) --profile replay run --rm \
	  -e KAFKA_BROKERS=redpanda:9092 \
	  archive-replayer \
	  --start-date 2024-01-01 --end-date 2024-02-01 --mode loadtest --delay-ms 0

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	@echo "Running PyFlink operator unit tests (no cluster needed)..."
	$(COMPOSE) run --rm --no-deps \
	  -e PYTHONPATH=/opt/flink/userjobs \
	  flink-jobmanager \
	  python -m pytest /opt/flink/userjobs/tests/ -v
	@echo ""
	@echo "Running Go unit tests..."
	docker run --rm \
	  -v $(PWD)/ingestion:/build \
	  -w /build \
	  golang:1.22-bookworm \
	  go test ./...
