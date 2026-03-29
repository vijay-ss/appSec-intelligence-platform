# infrastructure/flink/

Everything needed to run PyFlink with Kafka and MinIO checkpointing in Docker.

The base `apache/flink:1.20-python3` image ships with Python 3 but is missing
two things this project needs: the Kafka connector JAR and the S3 plugin for
MinIO checkpoint storage. This folder provides a custom Dockerfile that adds
both, plus config files that are mounted into the containers at runtime.

---

## Files

```
flink/
├── Dockerfile               # Custom image: adds Kafka JAR, S3 plugin, Python deps
├── requirements.txt         # Python packages installed into the Flink worker image
├── flink-conf.yaml          # Cluster config: RocksDB, checkpointing, memory, S3
└── log4j-console.properties # Logging config: suppresses framework noise
```

---

## Dockerfile

Extends `apache/flink:1.20-python3` with three additions:

**1 — Kafka connector JAR**

```
flink-sql-connector-kafka-3.3.0-1.20.jar  →  /opt/flink/lib/
```

Flink scans `/opt/flink/lib/` on startup and adds every JAR it finds to the
classpath. Without this JAR, submitting any topology that references
`FlinkKafkaConsumer` or `FlinkKafkaProducer` fails immediately with:

```
ClassNotFoundException: org.apache.flink.connector.kafka.source.KafkaSource
```

The version string `3.3.0-1.20` means connector version 3.3.0, built for
Flink 1.20. These must match your Flink version exactly. If you upgrade Flink,
update `KAFKA_CONNECTOR_VERSION` in the Dockerfile.

**2 — S3 / MinIO plugin**

```
flink-s3-fs-hadoop-*.jar  →  /opt/flink/plugins/s3-fs-hadoop/
```

The plugin is pre-bundled in the Flink distribution under `/opt/flink/opt/` —
it just needs to be moved to the plugins directory so Flink activates it. This
adds `s3://` URI support to `FileSystemCheckpointStorage`, which is what
`topology.py` uses to write checkpoints to MinIO.

**3 — Python operator dependencies**

The packages in `requirements.txt` are installed into the same Python
environment that Flink uses when it runs operator code. Flink spawns Python
worker processes to execute `flat_map()`, `process_element()` etc., and those
workers need to be able to `import psycopg2`, `import packaging`, and so on.

---

## flink-conf.yaml

Mounted at `/opt/flink/conf/flink-conf.yaml` in both containers, replacing the
default config. Key settings explained:

**Memory**
```yaml
jobmanager.memory.process.size: 1600m
taskmanager.memory.process.size: 1728m
```
Sized for a 16GB laptop. The taskmanager gets more because it holds RocksDB
state and runs the actual operator code. If you get OutOfMemoryError, bump
`taskmanager.memory.process.size` to `2048m` or higher.

**Task slots**
```yaml
taskmanager.numberOfTaskSlots: 4
parallelism.default: 2
```
Each slot can run one parallel instance of an operator. With 4 slots and
parallelism 2, the taskmanager can run the full topology with 2 slots to spare.
Raise parallelism to 4 for a load test, but keep it at 2 for day-to-day
development — lower parallelism means less memory and easier-to-read logs.

**State backend**
```yaml
state.backend: rocksdb
state.backend.incremental: true
state.backend.rocksdb.localdir: /tmp/flink-rocksdb
```
RocksDB stores keyed state (the dependency graph MapState, deduplicator
ValueState) on local disk rather than heap. `incremental: true` means only the
changed portions of state are uploaded to MinIO on each checkpoint, which is
much faster than full snapshots once the dep graph grows large.

**Checkpointing**
```yaml
state.checkpoints.dir: s3://flink-checkpoints/appsec
state.checkpoints.num-retained: 3
```
Checkpoints are written to MinIO every 60 seconds (the interval is set in
`topology.py` via `env.enable_checkpointing(60_000)`). If the Flink job
crashes and restarts, it picks up from the last checkpoint — no events are
lost and no events are double-processed.

**S3 / MinIO**
```yaml
s3.endpoint: http://minio:9000
s3.path.style.access: true
```
Points the S3 plugin at the local MinIO container. For production on AWS S3,
remove both of these lines — the plugin will use standard AWS endpoints.

---

## log4j-console.properties

Flink's default logging is very verbose — Kafka, Akka, Hadoop, and ZooKeeper
all emit INFO logs constantly, which makes it hard to see your operator output.
This config silences them to WARN/ERROR while keeping checkpoint and job
lifecycle logs at INFO.

---

## How the image fits into docker-compose

Both `flink-jobmanager` and `flink-taskmanager` use the same built image:

```yaml
flink-jobmanager:
  build:
    context: ./flink       # Dockerfile and requirements.txt are here
  image: appsec-flink:1.20 # Tag the built image so taskmanager reuses it
  volumes:
    - ./flink/flink-conf.yaml:/opt/flink/conf/flink-conf.yaml:ro
    - ../stream-processing:/opt/flink/userjobs:ro  # live-mounted operator code
```

The `stream-processing/` directory is mounted live at `/opt/flink/userjobs/`.
This means you can edit `operators/cve_join.py`, re-submit the job (`make flink`),
and see your changes immediately — no image rebuild needed.

---

## Running in Docker

The Flink cluster runs as two containers using this image.

```bash
# Build the image and start the cluster
make flink-up

# This does:
#   1. docker compose build flink-jobmanager  (builds this image)
#   2. docker compose up -d flink-jobmanager flink-taskmanager
#   3. Waits for jobmanager to be healthy
#   4. Submits topology.py via flink-job-submitter

# Dashboard: http://localhost:8081
```

### Editing operator code (no rebuild needed)

The `stream-processing/` directory is mounted live at `/opt/flink/userjobs/` in both containers. Editing any `.py` file takes effect on the next job submission:

```bash
# Edit operators/cve_join.py, then resubmit:
make flink
```

### Rebuilding the image

Only needed when you change `Dockerfile` or `requirements.txt` (i.e., you add a new Python package to an operator). Editing `.py` files does not require a rebuild.

```bash
# Rebuild and restart
docker compose -f infrastructure/docker-compose.yml build flink-jobmanager
docker compose -f infrastructure/docker-compose.yml up -d flink-jobmanager flink-taskmanager

# Or use make (rebuilds and resubmits in one step)
make flink
```

### Logs

```bash
make logs s=flink-jobmanager  # job lifecycle, checkpoint status
make logs s=flink-taskmanager # operator output, your structlog lines
```

---

## Troubleshooting

**Job fails immediately with `ClassNotFoundException`**
The Kafka connector JAR is not on the classpath. Check that the image built
successfully and the JAR is present:
```bash
docker exec $(docker compose -f infrastructure/docker-compose.yml ps -q flink-jobmanager) \
  ls /opt/flink/lib/ | grep kafka
```

**Checkpoints failing with `S3Exception`**
MinIO is not reachable or the `flink-checkpoints` bucket doesn't exist. Check:
```bash
# Is MinIO healthy?
curl http://localhost:9000/minio/health/live

# Did minio-init create the bucket?
docker compose -f infrastructure/docker-compose.yml logs minio-init
```

**`OutOfMemoryError` in taskmanager**
Increase `taskmanager.memory.process.size` in `flink-conf.yaml` and rebuild.

**Operators can't import a Python package**
The package is missing from `infrastructure/flink/requirements.txt`. Add it,
rebuild the image (`make flink` does this automatically), and resubmit.
