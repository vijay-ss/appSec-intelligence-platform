"""MCP posture and dependency graph tools."""
import os
import psycopg2
import psycopg2.extras


def get_team_exposure(team_name: str) -> dict:
    with psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT vm.cve_id, vm.service_id, vm.blast_radius, vm.sla_deadline, vm.status
                FROM vulnerability_matches vm
                WHERE vm.assigned_team = %s AND vm.status != 'resolved'
                ORDER BY vm.blast_radius DESC, vm.sla_deadline ASC
            """, (team_name,))
            return {"team": team_name, "vulnerabilities": [dict(r) for r in cur.fetchall()]}


def get_security_posture_summary() -> dict:
    with psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM posture_reports ORDER BY generated_at DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else {"message": "No posture reports yet — run the posture agent."}


def get_dependency_graph(service_id: str) -> dict:
    with psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT service_id, ecosystem, dependencies, snapshot_at
                FROM dep_graph_snapshots
                WHERE service_id = %s
                ORDER BY snapshot_at DESC LIMIT 1
            """, (service_id,))
            row = cur.fetchone()
            return dict(row) if row else {"service_id": service_id, "message": "No graph state yet."}
