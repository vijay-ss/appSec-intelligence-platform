"""
AppSec Intelligence — Topology Skeleton
========================================
A minimal topology for validating the Flink infrastructure before enabling
the full operator chain. Use this to confirm:

  1. The Kafka connector JAR is on the Flink classpath
  2. The broker address (redpanda:9092) resolves inside the Docker network
  3. Flink can read from and write to Kafka topics
  4. Checkpointing to MinIO is working
  5. The Flink dashboard at http://localhost:8081 shows a running job

This file does not import any operators. It reads from all three source topics,
logs a sample of each event to the task manager output, and writes raw events
through to a single debug sink topic (flink.debug.out).

Once this runs cleanly for a few minutes without errors, switch to topology.py
which has the full operator chain.

Usage:
  # Submit this skeleton instead of topology.py
  docker compose -f infrastructure/docker-compose.yml run --rm \
    flink-job-submitter \
    flink run --jobmanager flink-jobmanager:8081 \
              --python /opt/flink/userjobs/topology_skeleton.py \
              --pyFiles /opt/flink/userjobs \
              -d

  # Watch events flowing through
  make logs s=flink-taskmanager

  # Once healthy, switch to the real topology
  make flink
"""
import json
import os

from pyflink.common import Types
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import StreamExecutionEnvironment, CheckpointingMode
from pyflink.datastream.connectors.kafka import FlinkKafkaConsumer, FlinkKafkaProducer
from pyflink.datastream.state_backend import EmbeddedRocksDBStateBackend
from pyflink.datastream.checkpoint_storage import FileSystemCheckpointStorage


def kafka_props() -> dict:
    return {
        "bootstrap.servers": os.getenv("KAFKA_BROKERS", "localhost:9092"),
        "auto.offset.reset": "earliest",
    }


def consumer(topic: str, group: str) -> FlinkKafkaConsumer:
    return FlinkKafkaConsumer(
        topics=topic,
        deserialization_schema=SimpleStringSchema(),
        properties={**kafka_props(), "group.id": group},
    )


def producer(topic: str) -> FlinkKafkaProducer:
    return FlinkKafkaProducer(
        topic=topic,
        serialization_schema=SimpleStringSchema(),
        producer_config=kafka_props(),
    )


def log_event(label: str):
    """Return a map function that logs the first 120 chars of each event."""
    def _map(value: str) -> str:
        try:
            ev = json.loads(value)
            print(f"[{label}] source={ev.get('source', '?')} "
                  f"id={ev.get('cve_id') or ev.get('event_id', '?')[:12]} "
                  f"pkg={ev.get('affected_package') or ev.get('service_id', '?')}")
        except Exception:
            print(f"[{label}] raw={value[:80]}")
        return value
    return _map


def main():
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)  # Keep at 1 for skeleton — easier to read logs

    # Checkpointing — validates MinIO connectivity.
    # If this fails you'll see checkpoint errors in the job manager logs.
    env.enable_checkpointing(60_000, CheckpointingMode.EXACTLY_ONCE)
    env.set_state_backend(EmbeddedRocksDBStateBackend())
    env.get_checkpoint_config().set_checkpoint_storage(
        FileSystemCheckpointStorage(
            os.getenv("FLINK_CHECKPOINT_DIR", "s3://flink-checkpoints/appsec")
        )
    )

    # ── Sources ───────────────────────────────────────────────────────────────
    nvd_stream  = env.add_source(consumer("vulns.nvd.raw", "skeleton-nvd"),  source_name="nvd-source")
    osv_stream  = env.add_source(consumer("vulns.osv.raw", "skeleton-osv"),  source_name="osv-source")
    deps_stream = env.add_source(consumer("deps.changes",  "skeleton-deps"), source_name="deps-source")

    # ── Log a sample of each stream to task manager stdout ───────────────────
    # Watch with: make logs s=flink-taskmanager
    nvd_logged  = nvd_stream.map(log_event("NVD "), output_type=Types.STRING())
    osv_logged  = osv_stream.map(log_event("OSV "), output_type=Types.STRING())
    deps_logged = deps_stream.map(log_event("DEPS"), output_type=Types.STRING())

    # ── Merge all three streams and write to a debug sink topic ───────────────
    # Inspect the output in Redpanda console at http://localhost:8083
    # Topics → flink.debug.out
    (
        nvd_logged
        .union(osv_logged, deps_logged)
        .add_sink(producer("flink.debug.out"))
    )

    env.execute("appsec-intelligence-skeleton")


if __name__ == "__main__":
    main()
