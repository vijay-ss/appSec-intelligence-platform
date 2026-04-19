"""Service registry tool — fetch service metadata from PostgreSQL."""
import os
import psycopg2
import psycopg2.extras


_conn = None


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec"))
    return _conn


def get_service_metadata(service_id: str) -> dict:
    """Fetch service metadata from the service_registry table."""
    try:
        conn = _get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM service_registry WHERE service_id = %s", (service_id,))
            row = cur.fetchone()
            if row:
                return dict(row)
    except Exception:
        pass
    return {
        "service_id": service_id,
        "team": "unknown",
        "repo": service_id,
        "is_customer_facing": False,
        "pci_scope": False,
        "hipaa_scope": False,
        "soc2_scope": False,
        "pii_handler": False,
    }
