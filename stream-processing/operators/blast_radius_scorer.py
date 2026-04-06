"""
Blast Radius Scorer — enriches VulnerabilityMatchEvents with blast radius scores.

Fetches service metadata from the service registry (PostgreSQL via psycopg2)
and computes a composite score to determine alert priority.

Cache:
  Bounded LRU with 10,000 entry max. Removes oldest entries when full.

Composite score weights:
  CVSS score            40%  — base vulnerability severity
  Customer-facing       25%  — public-facing services have more exposure
  Compliance scope      20%  — PCI DSS / HIPAA / SOC 2 scope
  PII handler           15%  — services processing personal data

Score thresholds:
  CRITICAL  >= 0.75
  HIGH      >= 0.50
  MEDIUM    >= 0.25
  LOW        < 0.25
"""
import json
import os
from collections import OrderedDict
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras

try:
    from pyflink.datastream.functions import MapFunction, RuntimeContext
except ImportError:
    class MapFunction:  # type: ignore[no-redef]
        pass
    RuntimeContext = object  # type: ignore[assignment, misc]


MAX_CACHE_SIZE = 10000

SLA_HOURS = {
    "CRITICAL": 4,
    "HIGH": 24,
    "MEDIUM": 7 * 24,
    "LOW": 30 * 24,
}

class BlastRadiusScorerMap(MapFunction):
    """
    Enriches each VulnerabilityMatchEvent with:
      - blast_radius_tier (CRITICAL | HIGH | MEDIUM | LOW)
      - service_metadata (from registry cache or PostgreSQL)
      - sla_deadline
    """
    def open(self, runtime_context: RuntimeContext):
        self._conn = psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec"))
        self._conn.autocommit = True
        self._cache: OrderedDict = OrderedDict()
    
    def close(self):
        if self._conn:
            self._conn.close()
    
    def map(self, value: str) -> str:
        try:
            match = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return ""
        
        service_id = match.get("service_id", "")
        metadata = self._get_service_metadata(service_id)
        score = self._compute_score(match, metadata)
        tier = _tier_from_score(score)
        
        match["blast_radius_tier"] = tier
        match["service_metadata"] = metadata
        match["sla_deadline"] = (
            datetime.now(timezone.utc) + timedelta(hours=SLA_HOURS[tier])
        ).isoformat()
        
        return json.dumps(match)

    def _get_service_metadata(self, service_id: str) -> dict:
        """Fetch service metadata from PostgreSQL. Bounded LRU cache."""
        if service_id in self._cache:
            self._cache.move_to_end(service_id)
            return self._cache[service_id]
        
        try:
            with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM service_registry WHERE service_id = %s",
                    (service_id,),
                )
                row = cur.fetchone()
                meta = dict(row) if row else _default_metadata(service_id)
        except Exception:
            meta = _default_metadata(service_id)
        
        self._cache[service_id] = meta
        if len(self._cache) > MAX_CACHE_SIZE:
            self._cache.popitem(last=False)
        
        return meta
    
    def _compute_score(self, match: dict, meta: dict) -> float:
        cvss = min(match.get("cvss_score", 0.0), 10.0) / 10.0
        customer_facing = 1.0 if meta.get("is_customer_facing") else 0.0
        compliance = 1.0 if (meta.get("pci_scope") or meta.get("hipaa_scope") or meta.get("soc2_scope")) else 0.0
        pii = 1.0 if meta.get("pii_handler") else 0.0

        return (
            cvss * 0.40
            + customer_facing * 0.25
            + compliance * 0.20
            + pii * 0.15
        )


def _tier_from_score(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH"
    if score >= 0.25:
        return "MEDIUM"
    return "LOW"


def _default_metadata(service_id: str) -> dict:
    """Return safe defaults when a service is not in the registry."""
    return {
        "service_id": service_id,
        "team": "unknown",
        "ecosystem": "",
        "is_customer_facing": False,
        "pci_scope": False,
        "hipaa_scope": False,
        "soc2_scope": False,
        "pii_handler": False,
    }