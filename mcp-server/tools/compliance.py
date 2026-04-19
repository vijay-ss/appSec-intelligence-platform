"""MCP compliance gaps tool."""
import os
import psycopg2
import psycopg2.extras

FRAMEWORK_COLUMNS = {
    "pci_dss": "pci_scope",
    "hipaa": "hipaa_scope",
    "soc2": "soc2_scope",
    "iso27001": "soc2_scope",  # approximate mapping
}


def get_compliance_gaps(framework: str) -> dict:
    col = FRAMEWORK_COLUMNS.get(framework, "pci_scope")
    with psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT vm.cve_id, vm.service_id, vm.blast_radius, vm.sla_deadline
                FROM vulnerability_matches vm
                JOIN service_registry sr ON vm.service_id = sr.service_id
                WHERE sr.{col} = TRUE AND vm.status != 'resolved'
                ORDER BY vm.blast_radius DESC
            """)
            return {"framework": framework, "gaps": [dict(r) for r in cur.fetchall()]}
