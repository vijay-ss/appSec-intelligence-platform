"""
AppSec Intelligence — PyFlink Stream Processing Topology
=========================================================
Requires: apache-flink==1.19.0  (Python 3.11 recommended)

PyFlink API notes (important constraints):
  - Uses DataStream API only — Table API not needed here.
  - BroadcastProcessFunction IS available in Python API (added in 1.16).
  - KeyedProcessFunction with MapState/ValueState IS available.
  - EmbeddedRocksDBStateBackend IS available for keyed state.
  - Broadcast state is always in-memory by design — RocksDB does NOT back it.
    This is fine: we broadcast the CVE stream (~200 events/day), not the dep graph.
  - CEP (Complex Event Processing) is NOT available in the Python API — not used here.
  - FlinkKafkaConsumer/Producer require the Kafka connector JAR on the Flink classpath.
    The Dockerfile adds flink-sql-connector-kafka to /opt/flink/lib/.
  - StateTtlConfig IS available in Python API for automatic state expiry.
"""
import json
import os

from pyflink.common import Types
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import StreamExecutionEnvironment, CheckpointingMode
from pyflink.datastream.connectors.kafka import FlinkKafkaConsumer, FlinkKafkaProducer
from pyflink.datastream.state_backend import EmbeddedRocksDBStateBackend
from pyflink.datastream.checkpoint_storage import FileSystemCheckpointStorage

from operators.normaliser import NormaliserFlatMap
from operators.deduplicator import DeduplicatorProcess
from operators.dependency_graph import DependencyGraphProcess
from operators.cve_join import CVEBroadcastJoin
from operators.blast_radius_scorer import BlastRadiusScorerMap
from operators.router import RouterFlatMap


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


def main():
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(int(os.getenv("FLINK_PARALLELISM", "2")))

    # Exactly-once checkpointing every 60 seconds, stored in MinIO.
    env.enable_checkpointing(60_000, CheckpointingMode.EXACTLY_ONCE)

    # RocksDB state backend for keyed state (dependency graph grows large).
    # Note: broadcast state is always heap-based regardless of this setting.
    env.set_state_backend(EmbeddedRocksDBStateBackend())
    env.get_checkpoint_config().set_checkpoint_storage(
        FileSystemCheckpointStorage(
            os.getenv("FLINK_CHECKPOINT_DIR", "s3://flink-checkpoints/appsec")
        )
    )

    # ── Sources ───────────────────────────────────────────────────────────────
    nvd_stream  = env.add_source(consumer("vulns.nvd.raw", "flink-nvd"),  source_name="nvd-source")
    osv_stream  = env.add_source(consumer("vulns.osv.raw", "flink-osv"),  source_name="osv-source")
    deps_stream = env.add_source(consumer("deps.changes",  "flink-deps"), source_name="deps-source")

    # ── Vulnerability pipeline ────────────────────────────────────────────────

    # Step 1 — Normalise: both CVE sources → canonical VulnerabilityEvent JSON strings.
    # NormaliserFlatMap yields 0 events for malformed input (no exceptions propagated).
    vuln_stream = (
        nvd_stream
        .union(osv_stream)
        .flat_map(NormaliserFlatMap(), output_type=Types.STRING())
    )

    # Step 2 — Deduplicate: drop duplicate CVE+package+version combinations.
    # Uses KeyedProcessFunction with ValueState + StateTtlConfig (24h TTL).
    # Keyed by sha256(cve_id:package:ecosystem:version) for even distribution.
    deduped_vuln_stream = (
        vuln_stream
        .key_by(lambda x: _dedup_key(x))
        .process(DeduplicatorProcess(), output_type=Types.STRING())
    )

    # ── Dependency graph pipeline ─────────────────────────────────────────────

    # Step 3 — Maintain live dependency graph per service.
    # Uses KeyedProcessFunction with MapState (service_id → {pkg: version}).
    # Keyed by service_id so all updates for a service go to the same task.
    dep_graph_stream = (
        deps_stream
        .key_by(lambda x: json.loads(x).get("service_id", "unknown"))
        .process(DependencyGraphProcess(), output_type=Types.STRING())
    )

    # ── CVE × Dependency Graph Join ───────────────────────────────────────────
    #
    # Pattern: BroadcastProcessFunction
    #   - Broadcast side: CVE stream (small — ~200 events/day)
    #   - Non-broadcast side: dependency graph snapshots (the large stream)
    #
    # The CVE stream is broadcast to all parallel instances so each task can
    # check every incoming dep graph update against all recently seen CVEs.
    #
    # Broadcast state is heap-based (by Flink design). This is appropriate
    # because we only hold CVEs from the last 24h window — small dataset.
    # The large dep graph state stays in RocksDB as keyed state in Step 3.

    from pyflink.datastream.state import MapStateDescriptor

    cve_state_descriptor = MapStateDescriptor(
        "cve-broadcast",
        Types.STRING(),   # key:   cve_id
        Types.STRING(),   # value: VulnerabilityEvent JSON
    )

    cve_broadcast = deduped_vuln_stream.broadcast(cve_state_descriptor)

    match_stream = (
        dep_graph_stream
        .connect(cve_broadcast)
        .process(
            CVEBroadcastJoin(cve_state_descriptor),
            output_type=Types.STRING(),
        )
    )

    # Step 4 — Score blast radius for each match.
    scored_stream = (
        match_stream
        .map(BlastRadiusScorerMap(), output_type=Types.STRING())
        .filter(lambda x: x is not None and x != "")
    )

    # Step 5 — Route to severity-tiered output topics.
    # RouterFlatMap yields (topic, payload) string tuples.
    routed_stream = scored_stream.flat_map(
        RouterFlatMap(),
        output_type=Types.TUPLE([Types.STRING(), Types.STRING()]),
    )

    # ── Sinks ─────────────────────────────────────────────────────────────────
    for tier in ("critical", "high", "medium", "low"):
        topic = f"vuln.matches.{tier}"
        (
            routed_stream
            .filter(lambda x, t=topic: x[0] == t)
            .map(lambda x: x[1], output_type=Types.STRING())
            .add_sink(producer(topic))
        )

    (
        routed_stream
        .filter(lambda x: x[0] == "deps.risk.prs")
        .map(lambda x: x[1], output_type=Types.STRING())
        .add_sink(producer("deps.risk.prs"))
    )

    dep_graph_stream.add_sink(producer("vuln.graph.snapshots"))

    env.execute("appsec-intelligence")


def _dedup_key(event_json: str) -> str:
    """Extract deduplication key from a VulnerabilityEvent JSON string."""
    import hashlib
    try:
        ev = json.loads(event_json)
        raw = f"{ev.get('cve_id','')}:{ev.get('affected_package','')}:{ev.get('ecosystem','')}:{ev.get('affected_version_range','')}"
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception:
        return event_json[:64]


if __name__ == "__main__":
    main()
