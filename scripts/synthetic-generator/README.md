# Synthetic Generator

A Python container that makes the platform demonstrable without waiting for real CVEs to hit real repos. It runs continuously alongside the live pipeline and serves two functions: a background hum of realistic dependency change events, and an HTTP endpoint for firing named demo scenarios on demand.

---

## Why it exists

Real data sources produce gradual, unpredictable activity. You can't guarantee that a newsworthy CVE will land in a PCI-scoped service during a demo. The synthetic generator lets you inject exactly the scenario you need — a critical RCE in three payment services, a supply chain attack, a safe upgrade wave — at the press of a button.

The 50 synthetic services in the registry are designed to produce dramatically different blast radius scores (`checkout-api` with PCI scope scores very differently from an internal `ml-training-worker`), which makes the alert routing and triage more interesting to watch.

---

## Running in Docker

The generator starts automatically as part of the full stack:

```bash
make up    # synthetic-generator starts alongside everything else
```

Or start it individually after infrastructure is running:

```bash
docker compose -f infrastructure/docker-compose.yml up -d synthetic-generator
```

### Watch the output

```bash
make logs s=synthetic-generator

# Directly
docker compose -f infrastructure/docker-compose.yml logs -f synthetic-generator
```

You should see dependency change events being emitted at ~2/sec:

```
{"service":"synthetic-generator","level":"info","event":"emitted","package":"requests","version":"2.28.0","service_id":"checkout-api"}
{"service":"synthetic-generator","level":"info","event":"emitted","package":"urllib3","version":"2.0.7","service_id":"auth-service"}
```

Watch them arrive in the Redpanda console at [http://localhost:8080](http://localhost:8080) → Topics → `deps.changes`.

### Rebuild after code changes

```bash
make rebuild s=synthetic-generator
```

---

## Firing a scenario

```bash
# Via make (default scenario: critical_rce)
make scenario

# With a specific scenario
make scenario SCENARIO=mass_exposure
make scenario SCENARIO=supply_chain_attack

# Via curl directly
curl -X POST http://localhost:8090/scenario \
     -H "Content-Type: application/json" \
     -d '{"scenario": "critical_rce"}'

# List available scenarios
curl http://localhost:8090/scenarios
```

---

## Running without Docker (optional)

```bash
docker compose -f infrastructure/docker-compose.yml up -d redpanda postgres

cd scripts/synthetic-generator
pip install -r requirements.txt

export KAFKA_BROKERS=localhost:9092
export POSTGRES_URL=postgresql://appsec:appsec@localhost:5432/appsec

python main.py --mode hum
```

---

## Scenarios

### `critical_rce`
Pins `requests==2.28.0` (affected by CVE-2024-35195) into three PCI-scoped customer-facing services: `checkout-api`, `payment-processor`, and `auth-service`. Expected outcome: three CRITICAL blast radius triage reports, alerts routed to the payments team.

### `mass_exposure`
Pins `cryptography==41.0.0` (affected by CVE-2024-0727 and CVE-2023-49083) into eight services across four teams. Expected outcome: demonstrates blast radius scoring producing different tiers for the same CVE in different services — `auth-service` (CRITICAL) vs `ml-training-worker` (HIGH).

### `supply_chain_attack`
Adds `PyYAML==5.3.1` — a version with a known arbitrary code execution vulnerability — to `checkout-api`. This event goes to `deps.risk.prs` because it's an addition rather than a bump. Expected outcome: PR Risk Agent posts a BLOCK verdict.

### `log4shell_redux`
Pins `log4j:log4j==1.2.17` and `org.springframework:spring-webmvc==5.3.0` into legacy Java services. Expected outcome: Maven ecosystem detection and multi-CVE detection in a single triage report.

### `safe_upgrade_wave`
Bumps `requests` from `2.28.0` to `2.32.1` (the safe version) in ten services simultaneously. Expected outcome: **no alerts fire**. Validates that the pipeline correctly identifies safe versions and does not emit false positives.

### `pr_risk_safe`
Adds `httpx==0.27.0` to `checkout-api`. No known CVEs at this version. Expected outcome: PR Risk Agent posts an APPROVE verdict.

---

## Environment variables

| Variable | Default (in container) | Description |
|---|---|---|
| `KAFKA_BROKERS` | `redpanda:9092` | `redpanda:9092` in Docker, `localhost:9092` from host |
| `POSTGRES_URL` | `postgresql://appsec:appsec@postgres:5432/appsec` | `postgres` in Docker, `localhost` from host |
| `HUM_RATE` | `2.0` | Background events per second |
| `SEED_REGISTRY` | `true` | Seed the service registry on startup |

---

## Service Registry — `registry.py`

Defines 50 fictional microservices seeded into PostgreSQL `service_registry` on container startup.

| Team | Services | Key characteristics |
|---|---|---|
| payments | checkout-api, payment-processor, invoice-generator, fraud-detector, billing-scheduler, legacy-billing | PCI DSS scope, customer-facing, PII handlers |
| auth | auth-service, session-manager, permissions-api | PCI + HIPAA scope, customer-facing |
| platform | api-gateway, config-service, secrets-manager, log-aggregator, metrics-collector | Mix of SOC 2 scope, internal |
| product | user-api, notification-worker, search-api, recommendations-api | Customer-facing, PII handlers |
| frontend | storefront, admin-portal, mobile-bff | npm ecosystem, customer-facing |
| data | data-pipeline, reporting-service, ml-training-worker, feature-store-api | Internal, PII handlers |
| legacy | legacy-billing, document-processor | Maven ecosystem, migration in progress |

About 30% of services are seeded with known-vulnerable package versions so the pipeline fires end-to-end without requiring a scenario to be triggered manually.
