# Stream Processing Layer

A single PyFlink job that continuously joins two independent streams — CVE vulnerability publications and dependency graph updates — and enriches each match with a blast radius score before routing it to a severity-tiered output topic.

The core data engineering challenge: a CVE can arrive before or after the service that's vulnerable to it updates its dependencies. The pipeline must handle both orderings correctly, in real time, without losing events or producing duplicates. PyFlink's stateful stream processing with exactly-once checkpointing to MinIO handles this.

---

## Architecture

```
vulns.nvd.raw  ──-┐
                  ├─► Normaliser ──► Deduplicator ────────────────────────--──┐
vulns.osv.raw  ──-┘                                                           │ broadcast
                                                                              ▼
deps.changes ───────────────────────► Dependency Graph ──► CVE Join ──► Blast Radius ──► Router
                                        (keyed, RocksDB)   (broadcast)                      │
                                                                                             ▼
                                                             vuln.matches.{critical,high,medium,low}
                                                             deps.risk.prs
                                                             vuln.graph.snapshots
```

---

## Running in Docker

The Flink cluster runs as two containers built from `infrastructure/flink/Dockerfile`. The `stream-processing/` directory is **mounted live** into both containers — you can edit operator `.py` files without rebuilding the image.

### Start the cluster and submit the topology

```bash
# Start infrastructure first, then Flink
make infra-up
make flink-up
```

`make flink-up` does three things:
1. Builds the custom Flink Docker image (downloads Kafka connector JAR ~5MB, first time only)
2. Starts `flink-jobmanager` and `flink-taskmanager`
3. Runs `flink-job-submitter` which submits `topology.py` then exits

The Flink dashboard is at [http://localhost:8081](http://localhost:8081). Once the topology is submitted you'll see the 6-operator DAG with live throughput metrics.

### Watch the logs

```bash
# Job manager — job lifecycle events, checkpoint status
make logs s=flink-jobmanager

# Task manager — operator output, your structlog lines from operator code
make logs s=flink-taskmanager
```

### Resubmit after editing operator code

Because `stream-processing/` is mounted live, editing a `.py` file takes effect on the next job submission — no image rebuild needed:

```bash
# Edit operators/cve_join.py, then resubmit
make flink
```

`make flink` rebuilds the Flink image and resubmits the topology in one step. If you only changed Python files (not `Dockerfile` or `requirements.txt`), Docker's build cache means the rebuild is instant.

### Rebuild the image

The image only needs a full rebuild when you change `infrastructure/flink/Dockerfile` or `infrastructure/flink/requirements.txt` (i.e., you add a new Python import to an operator):

```bash
docker compose -f infrastructure/docker-compose.yml build flink-jobmanager
make flink
```

---

## Running unit tests (no cluster needed)

Every operator is a plain Python class. The unit tests call operator logic directly — no Flink cluster, no Kafka, no Docker required for the tests themselves.

```bash
# Run tests inside the Flink container (same Python environment as production)
make test
```

Expected output:

```
tests/test_operators.py::TestNormaliser::test_valid_osv_event PASSED
tests/test_operators.py::TestNormaliser::test_malformed_json_dropped PASSED
tests/test_operators.py::TestVersionMatching::test_version_range_less_than PASSED
tests/test_operators.py::TestBlastRadiusScorer::test_critical_all_factors PASSED
... 12 passed in 0.34s
```

### Invoke an operator directly inside the container

```bash
docker compose -f infrastructure/docker-compose.yml run --rm --no-deps \
  -e PYTHONPATH=/opt/flink/userjobs \
  flink-jobmanager \
  python3 -c "
import json
from unittest.mock import MagicMock
from operators.normaliser import NormaliserFlatMap

op = NormaliserFlatMap()
op.open(MagicMock())

raw = json.dumps({
    'event_id': 'test-1', 'cve_id': 'CVE-2024-1234', 'source': 'osv',
    'published_at': '2024-01-01T00:00:00Z', 'ingested_at': '2024-01-01T00:00:00Z',
    'cvss_score': 9.1, 'affected_package': 'requests', 'ecosystem': 'pypi',
})

results = list(op.flat_map(raw))
print(json.dumps(json.loads(results[0]), indent=2))
"
```

---

## Running without Docker (optional)

Unit tests don't need the cluster at all. To run topology.py locally for development, start infrastructure in Docker and connect from your machine:

```bash
# Start Flink cluster in Docker
make flink-up

# Or just run the tests natively if you have Python 3.11 and apache-flink installed
cd stream-processing
pip install -r requirements.txt
pytest tests/ -v
```

---

## Environment variables

| Variable | Default (in container) | Description |
|---|---|---|
| `KAFKA_BROKERS` | `redpanda:9092` | Set in `flink-conf.yaml` via jobmanager env |
| `POSTGRES_URL` | `postgresql://appsec:appsec@postgres:5432/appsec` | For blast radius scorer metadata lookups |
| `AWS_ACCESS_KEY_ID` | `minioadmin` | MinIO credentials for checkpoint storage |
| `AWS_SECRET_ACCESS_KEY` | `minioadmin` | MinIO credentials for checkpoint storage |

These are set in `infrastructure/docker-compose.yml` and passed through to the Flink worker processes automatically.

---

## PyFlink version and API constraints

**Version:** `apache-flink==2.0.0` (Python 3.11 recommended)

| Feature | Available in Python API? | Used here |
|---|---|---|
| `FlatMapFunction` | ✅ | Normaliser, Router |
| `KeyedProcessFunction` | ✅ | Deduplicator, Dependency Graph |
| `BroadcastProcessFunction` | ✅ (since 1.16) | CVE Join |
| `MapState`, `ValueState` | ✅ | Deduplicator, Dependency Graph |
| `StateTtlConfig` | ✅ | Deduplicator (24h TTL) |
| `EmbeddedRocksDBStateBackend` | ✅ | Dependency Graph (large state) |
| CEP / Pattern matching | ❌ Java only | Not used |

Broadcast state is always heap-based by Flink's design. This is why the CVE stream (~200 events/day) is the broadcast side and the dependency graph (large) is the keyed side.

---

## Operators

### `normaliser.py` — `FlatMapFunction`

Validates and normalises raw CVE JSON from `vulns.nvd.raw` and `vulns.osv.raw`. Uses `FlatMapFunction` so it can yield zero elements for malformed records — bad records never propagate downstream.

### `deduplicator.py` — `KeyedProcessFunction`

The same CVE is routinely published by both NVD and OSV. The deduplicator keys on `sha256(cve_id:package:ecosystem:version_range)` and uses a `ValueState<Boolean>` per key with a 24-hour TTL. First event passes through; duplicates are dropped; re-published CVEs a day later are processed again.

### `dependency_graph.py` — `KeyedProcessFunction` + `MapState`

Maintains a live `{package_name → pinned_version}` dictionary for every service, keyed by `service_id`. Applies `added`, `removed`, and `updated` deltas from each `DependencyChangeEvent`. Emits a full snapshot after every update. RocksDB-backed — handles hundreds of entries per service without impacting heap.

### `cve_join.py` — `BroadcastProcessFunction`

Joins dep graph snapshots against broadcast CVE state. CVEs are broadcast to all parallel task instances so each can check incoming snapshots against all recently seen CVEs without inter-task coordination. Uses the `packaging` library for version range matching.

### `blast_radius_scorer.py` — `MapFunction`

Composite risk score using four weighted factors: CVSS severity (40%), customer-facing (25%), compliance scope (20%), PII handler (15%). Fetches service metadata from PostgreSQL with an in-process dict cache. Sets SLA deadline: CRITICAL=4h, HIGH=24h, MEDIUM=7d, LOW=30d.

### `router.py` — `FlatMapFunction`

Routes scored matches to severity-tiered Kafka sinks: `vuln.matches.critical`, `.high`, `.medium`, `.low`, `deps.risk.prs`, `vuln.graph.snapshots`.
