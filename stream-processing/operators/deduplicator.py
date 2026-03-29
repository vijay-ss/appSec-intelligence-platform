"""
Deduplicator — drops duplicate CVE events using keyed ValueState with TTL.

PyFlink API used:
  - KeyedProcessFunction: applied on a KeyedStream, gives access to per-key state.
  - ValueStateDescriptor + StateTtlConfig: state auto-expires after 24h.
    StateTtlConfig IS available in the Python API.

The stream is keyed by sha256(cve_id:package:ecosystem:version_range)
before this operator, ensuring duplicate CVEs from NVD and OSV land on
the same task instance and are caught by the same state cell.
"""
import json

try:
    from pyflink.datastream.functions import KeyedProcessFunction, RuntimeContext
    from pyflink.datastream.state import ValueStateDescriptor, StateTtlConfig
    from pyflink.common import Types
    from pyflink.common.time import Time
except ImportError:
    class KeyedProcessFunction:  # type: ignore[no-redef]
        class Context:
            pass
    RuntimeContext = object  # type: ignore[assignment, misc]
    ValueStateDescriptor = object  # type: ignore[assignment, misc]
    StateTtlConfig = object  # type: ignore[assignment, misc]
    Types = object  # type: ignore[assignment, misc]
    Time = object  # type: ignore[assignment, misc]


class DeduplicatorProcess(KeyedProcessFunction):
    """Emit each unique CVE event exactly once. Duplicates within 24h are dropped."""
    
    def open(self, runtime_context: RuntimeContext):
        # StateTtlConfig cleans up state automatically after 24h,
        # preventing unbounded state growth.
        ttl_config = (
            StateTtlConfig
            .new_builder(Time.hours(24))
            .set_update_type(StateTtlConfig.UpdateType.OnCreateAndWrite)
            .set_state_visibility(StateTtlConfig.StateVisibility.NeverReturnExpired)
            .build()
        )
        descriptor = ValueStateDescriptor("seen", Types.BOOLEAN())
        descriptor.enable_time_to_live(ttl_config)
        self.seen = runtime_context.get_state(descriptor)
    
    def process_element(self, value: str, ctx: "KeyedProcessFunction.Context"):
        """Yield the event if it hasn't been seen in the TTL window, else drop it."""
        if self._seen.value() is None:
            self._seen.update(True)
            yield value