"""
Normaliser — maps raw NVD and OSV JSON to canonical VulnerabilityEvent JSON.

Uses FlatMapFunction (yields 0 or 1 elements per input).
Yielding 0 elements is the clean way to drop malformed records in PyFlink.
"""
import json
from datetime import datetime, timezone

try:
    from pyflink.datastream.functions import FlatMapFunction, RuntimeContext
except ImportError:
    class FlatMapFunction:  # type: ignore[no-redef]
        pass
    RuntimeContext = object  # type: ignore[assignment, misc]

class NormaliserFlatMap(FlatMapFunction):
    """Normalise raw CVE records from NVD or OSV to a canonical schema."""
    
    def open(self, runtime_context: RuntimeContext):
        pass
    
    def flat_map(self, value: str):
        """
        Parse and normalise a raw CVE JSON string.
        Yields the normalised JSON string, or nothing if the record is unusable.
        """
        try:
            raw = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
        
        source = raw.get("source", "")
        if source.lower() not in ("nvd", "osv"):
            return
        
        cve_id = raw.get("cve_id", "")
        if not cve_id:
            return
        
        cvss = raw.get("cvss", 0.0)
        if not raw.get("severity_tier"):
            raw["severity_tier"] = _severity_from_cvss(cvss)
        
        if not raw.get("ingested_at"):
            raw["ingested_at"] = datetime.now(timezone.utc).isoformat()
        
        yield json.dumps(raw)
    
    
def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"