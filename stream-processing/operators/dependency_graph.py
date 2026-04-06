"""
Dependency Graph Operator — maintains a live per-service dependency snapshot.

PyFlink API used:
  - KeyedProcessFunction on a KeyedStream (keyed by service_id).
  - MapState: maps package_name → pinned_version for each service.
    MapState with RocksDB backend supports large state efficiently.
  - Yields a dep graph snapshot JSON after every update.

The snapshot is consumed by:
  1. The CVE join operator (via Broadcast connect)
  2. The vuln.graph.snapshots Kafka topic (for downstream consumers)
"""
import json
from datetime import datetime, timezone

try:
    from pyflink.datastream.functions import KeyedProcessFunction, RuntimeContext
    from pyflink.datastream.state import MapStateDescriptor
    from pyflink.common import Types
except ImportError:
    class KeyedProcessFunction:  # type: ignore[no-redef]
        class Context: pass
    RuntimeContext = object  # type: ignore[assignment, misc]
    MapStateDescriptor = object  # type: ignore[assignment, misc]
    Types = object  # type: ignore[assignment, misc]
    
class DependencyGraphProcess(KeyedProcessFunction):
    """
    Maintains a live dependency graph for each service_id.
    On each DependencyChangeEvent, applies the delta and emits an updated snapshot.
    """
    
    def open(self, runtime_context: RuntimeContext):
        # MapState: package_name → pinned_version
        # Stored in RocksDB - handles large dependency trees without heap pressure
        self._deps = runtime_context.get_map_state(
            MapStateDescriptor("dep-graph", Types.STRING(), Types.STRING())
        )
        self._service_id = None
    
    def process_element(self, value: str, ctx: "KeyedProcessFunction.Context"):
        """Apply a DependencyChangeEvent delta to the service's graph state."""
        try:
            event = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
    
        service_id = event.get("service_id", "unknown")
        
        for pin in event.get("removed") or []:
            pkg = pin.get("package", "")
            if pkg and self._deps.contains(pkg):
                self._deps.remove(pkg)
        
        for pin in event.get("added") or []:
            pkg = pin.get("package", "")
            ver = pin.get("version", "")
            if pkg and ver:
                self._deps.put(pkg, ver)
        
        for update in event.get("updated") or []:
            pkg = update.get("package", "")
            to_ver = update.get("to_version", "")
            if pkg and to_ver:
                self._deps.put(pkg, to_ver)
        
        snapshot = {
            "service_id": service_id,
            "ecosystem": event.get("ecosystem", ""),
            "dependencies": {k: v for k, v in self._deps.items()},
            "snapshot_at": datetime.now(timezone.utc).isoformat(),
            "trigger_event_id": event.get("event_id", ""),
        }
        yield json.dumps(snapshot)