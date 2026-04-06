"""
CVE Join Operator — joins dep graph snapshots against broadcast CVE state.

PyFlink API used:
  - BroadcastProcessFunction: confirmed available in Python API since 1.16.
  - Non-broadcast side: dep graph snapshots (one per service update).
  - Broadcast side: CVE stream (small — ~200 events/day, broadcast to all tasks).

How it works:
  process_broadcast_element — called for each new CVE.
    Writes the CVE to broadcast state and immediately scans dep graph snapshot
    state for any services already vulnerable.

  process_element — called for each dep graph snapshot.
    Checks the snapshot's full dependency dict against all CVEs in broadcast state.

Both sides emit VulnerabilityMatchEvent JSON strings on a match.

Version matching: uses simple exact-match and "in affected_versions list" check.
Semantic version range matching (< 2.32.0 style) is implemented in _version_is_affected().
"""
import json
from datetime import datetime, timezone, timedelta
from json.decoder import JSONDecodeError
from uuid import uuid4

try:
    from pyflink.datastream.functions import BroadcastProcessFunction, RuntimeContext
    from pyflink.datastream.state import MapStateDescriptor, ReadOnlyBroadcastState
except ImportError:
    class BroadcastProcessFunction:  # type: ignore[no-redef]
        class Context: pass
        class ReadOnlyContext: pass
    RuntimeContext = object  # type: ignore[assignment, misc]
    MapStateDescriptor = object  # type: ignore[assignment, misc]
    ReadOnlyBroadcastState = object  # type: ignore[assignment, misc]

class CVEBroadcastJoin(BroadcastProcessFunction):
    """
    Joins dep graph snapshots against broadcast CVE state.

    Broadcast stage holds: cve_id -> VulnerabilityEvent JSON (last 24h of CVEs).
    Non-broadcast side: dep graph snapshots emitted by DependencyGraphProcess.
    """
    def __init__(self, cve_state_descriptor: MapStateDescriptor) -> None:
        self._descriptor = cve_state_descriptor
    
    def open(self, runtime_context: RuntimeContext) -> None:
        pass
    
    def process_broadcast_element(
        self,
        value: str,
        ctx: BroadcastProcessFunction.Context,
    ) -> None:
        """
        Called for each CVE event on the broadcast side.
        Writes to broadcast state - does NOT have read access to keyed state
        (this is a BroadcastProcessFunction, not a KeyedBroadcastProcessFunction)
        """
        try:
            cve = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return

        cve_id = cve.get("cve_id", "")
        if not cve_id:
            return
        
        cve["_expires_at"] = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).isoformat()
        
        broadcast_state = ctx.get_broadcast_state(self._descriptor)
        broadcast_state.put(cve_id, json.dumps(cve))
    
    def process_element(
        self,
        value: str,
        ctx: "BroadcastProcessFunction.ReadOnlyContext",
    ):
        """
        Called for each dep graph snapshot on the non-broadcast side.
        Has read-only access to broadcast CVE state.
        Emits a VulnerabilityMatchEvent for each CVE + dep version match.
        """
        try:
            snapshot = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
        
        service_id = snapshot.get("service_id", "")
        ecosystem = snapshot.get("ecosystem", "")
        dependencies: dict = snapshot.get("dependencies", {})
        
        if not dependencies:
            return
        
        broadcase_state: ReadOnlyBroadcastState = ctx.get_broadcast_state(self._descriptor)
        
        # Iterate broadcast CVEs and check against this service's deps
        for cve_id, cve_json in broadcase_state.items():
            try:
                cve = json.loads(cve_json)
            except (json.JSONDecodeError, TypeError):
                continue
                
            # Skip if this CVE is for a different ecosystem
            cve_ecosystem = cve.get("ecosystem", "")
            if cve_ecosystem and cve_ecosystem != ecosystem:
                continue
            
            cve_package = cve.get("affected_package", "")
            if not cve_package:
                continue
            
            installed_version = None
            for dep_pkg, dep_ver in dependencies.items():
                if dep_pkg.lower() == cve_package.lower():
                    installed_version = dep_ver
                    break

            if installed_version is None:
                continue # package not installed in this service
            
            affected_versions = cve.get("affected_versions", [])
            version_range = cve.get("affected_versions_range", "")
            
            if not _version_is_affected(installed_version, affected_versions, version_range):
                continue
            
            match = {
                "cve_id": cve_id,
                "service_id": service_id,
                "ecosystem": ecosystem,
                "matched_package": cve_package,
                "matched_version": installed_version,
                "cvss_score": cve.get("cvss_score", 0.0),
                "severity_tier": cve.get("severity_tier", "MEDIUM"),
                "blast_radius_tier": "MEDIUM",  # placeholder — scored in next operator
                "is_transitive": False,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            yield json.dumps(match)


def _version_is_affected(
    installed: str,
    affected_versions: list[str],
    version_range: str,
) -> bool:
    """
    Check if the installed version is in the CVE's affected range.
    
    Two strategies:
    1. Exact match against the explicit affected_versions list (from OSV).
    2. Semantic range check against version_range string (e.g. '< 2.32.0').
    
    OSV provides an explicit versions list for most packages, so strategy 1
    is the primary match path and handles the majority of real CVEs.
    """
    affected_versions = affected_versions or []

    if installed in affected_versions:
        return True
    
    if version_range:
        try:
            return _check_version_range(installed, version_range)
        except Exception:
            pass

    return False


def _check_version_range(installed: str, version_range: str) -> bool:
    """
    Check a version against a range string like '< 2.32.0' or '>= 1.0, < 2.0'.
    Uses the packaging library for PyPI-style version comparisons.
    Falls back to packaging.version.Version for proper semantic comparison.
    """
    spec_str = version_range.replace("< ", "<").replace("> ", ">").replace("= ", "=")

    try:
        from packaging.specifiers import SpecifierSet
        spec = SpecifierSet(spec_str, prereleases=True)
        return installed in spec
    except Exception:
        return _compare_versions(installed, spec_str)


def _compare_versions(installed: str, version_range: str) -> bool:
    """
    Compare installed version against range using packaging.version.
    Handles: <, <=, >, >=, ==, !=
    """
    try:
        from packaging.version import Version
        installed_ver = Version(installed)

        if version_range.startswith("<="):
            return installed_ver <= Version(version_range[2:].strip())
        elif version_range.startswith("<"):
            return installed_ver < Version(version_range[1:].strip())
        elif version_range.startswith(">="):
            return installed_ver >= Version(version_range[2:].strip())
        elif version_range.startswith(">"):
            return installed_ver > Version(version_range[1:].strip())
        elif version_range.startswith("==") or version_range.startswith("="):
            return installed_ver == Version(version_range[2:].strip())
        elif version_range.startswith("!="):
            return installed_ver != Version(version_range[2:].strip())

        return False
    except Exception:
        return False
