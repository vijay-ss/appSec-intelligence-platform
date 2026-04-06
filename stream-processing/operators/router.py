"""
Router — routes scored VulnerabilityMatchEvents to severity-tiered Kafka topics.

Uses FlatMapFunction yielding (topic, payload) string tuples.
The topology wires each tier to its own Kafka sink.
"""
import json

try:
    from pyflink.datastream.functions import FlatMapFunction, RuntimeContext
except ImportError:
    class FlatMapFunction:  # type: ignore[no-redef]
        pass
    RuntimeContext = object  # type: ignore[assignment, misc]

SEVERITY_TOPICS = {
    "CRITICAL": "vuln.matches.critical",
    "HIGH":     "vuln.matches.high",
    "MEDIUM":   "vuln.matches.medium",
    "LOW":      "vuln.matches.low",
}


class RouterFlatMap(FlatMapFunction):
    """Route each match to the appropriate severity-tiered Kafka topic."""

    def open(self, runtime_context: RuntimeContext):
        pass

    def flat_map(self, value: str):
        try:
            match = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return

        tier = match.get("blast_radius_tier", "LOW")

        # Route to severity topic.
        topic = SEVERITY_TOPICS.get(tier, "vuln.matches.low")
        yield (topic, value)

        # PR risk events go to a separate topic when the change was an addition.
        if match.get("is_new_dependency"):
            yield ("deps.risk.prs", value)
