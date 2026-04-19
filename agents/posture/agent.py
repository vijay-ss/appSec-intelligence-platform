"""
Daily Posture Agent
===================
Runs at 06:00 UTC every day (scheduled via cron or APScheduler).

Queries PostgreSQL for the current security state, maps findings to compliance
frameworks, and generates a plain-English executive summary using the LLM.

Writes a PostureReport to:
  - PostgreSQL posture_reports table
  - MinIO as a dated JSON file (s3://appsec-backups/posture/YYYY-MM-DD.json)

The MCP tool get_security_posture_summary reads the most recent row from
posture_reports to answer questions like "what's our security posture this week?".
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta

from minio import Minio
import psycopg2
import psycopg2.extras

from agents.llm_provider import get_llm

log = logging.getLogger(__name__)

POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")
MINIO_ENDPOINT   = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE     = os.getenv("MINIO_SECURE", "false").lower() == "true"  # False for local HTTP


# ── Data gathering ────────────────────────────────────────────────────────────

def _fetch_posture_data(conn) -> dict:
    """Run all the SQL queries needed to build the posture report."""
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:

        cur.execute("""
            SELECT blast_radius_tier, COUNT(*) as count
            FROM vulnerability_matches
            WHERE status = 'open'
            GROUP BY blast_radius_tier
        """)
        tier_counts = {row["blast_radius_tier"]: row["count"] for row in cur.fetchall()}

        # SLA breaches — findings past their deadline
        cur.execute("""
            SELECT COUNT(*) as count
            FROM vulnerability_matches
            WHERE status = 'open' AND sla_deadline < NOW()
        """)
        past_sla = cur.fetchone()["count"]

        # MTTD — mean time from CVE publication to detection, last 30 days
        cur.execute("""
            SELECT AVG(EXTRACT(EPOCH FROM (detected_at - published_at)) / 60) as mttd_minutes
            FROM vulnerability_matches vm
            JOIN vulnerabilities v ON vm.cve_id = v.cve_id
            WHERE vm.detected_at > NOW() - INTERVAL '30 days'
        """)
        row = cur.fetchone()
        mttd_minutes = round(float(row["mttd_minutes"] or 0), 1)

        # MTTR — mean time from detection to status='resolved', last 30 days
        cur.execute("""
            SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at)) / 86400) as mttr_days
            FROM vulnerability_matches
            WHERE status = 'resolved'
              AND resolved_at > NOW() - INTERVAL '30 days'
        """)
        row = cur.fetchone()
        mttr_days = round(float(row["mttr_days"] or 0), 1)

        # Previous 30-day window for trend comparison
        cur.execute("""
            SELECT COUNT(*) as count
            FROM vulnerability_matches
            WHERE status = 'open'
              AND detected_at BETWEEN NOW() - INTERVAL '60 days' AND NOW() - INTERVAL '30 days'
        """)
        prev_open = cur.fetchone()["count"]

        cur.execute("""
            SELECT COUNT(*) as count
            FROM vulnerability_matches
            WHERE status = 'open'
              AND detected_at > NOW() - INTERVAL '30 days'
        """)
        curr_open = cur.fetchone()["count"]

        # Per-team exposure
        cur.execute("""
            SELECT sr.team, COUNT(*) as count
            FROM vulnerability_matches vm
            JOIN service_registry sr ON vm.service_id = sr.service_id
            WHERE vm.status = 'open'
            GROUP BY sr.team
            ORDER BY count DESC
        """)
        team_exposure = {row["team"]: row["count"] for row in cur.fetchall()}

        # Compliance gaps
        cur.execute("""
            SELECT
                SUM(CASE WHEN sr.pci_scope THEN 1 ELSE 0 END) as pci_gaps,
                SUM(CASE WHEN sr.hipaa_scope THEN 1 ELSE 0 END) as hipaa_gaps,
                SUM(CASE WHEN sr.soc2_scope THEN 1 ELSE 0 END) as soc2_gaps
            FROM vulnerability_matches vm
            JOIN service_registry sr ON vm.service_id = sr.service_id
            WHERE vm.status = 'open'
        """)
        row = cur.fetchone()
        compliance_gaps = {
            "pci_dss": int(row["pci_gaps"] or 0),
            "hipaa": int(row["hipaa_gaps"] or 0),
            "soc2": int(row["soc2_gaps"] or 0),
        }

    # Trend direction
    if prev_open == 0:
        trend = "stable"
    elif curr_open < prev_open * 0.9:
        trend = "improving"
    elif curr_open > prev_open * 1.1:
        trend = "degrading"
    else:
        trend = "stable"

    return {
        "open_critical": tier_counts.get("CRITICAL", 0),
        "open_high": tier_counts.get("HIGH", 0),
        "open_medium": tier_counts.get("MEDIUM", 0),
        "open_low": tier_counts.get("LOW", 0),
        "past_sla_count": past_sla,
        "mttd_minutes": mttd_minutes,
        "mttr_days": mttr_days,
        "trend_direction": trend,
        "team_exposure": team_exposure,
        "compliance_gaps": compliance_gaps,
    }


# ── LLM narrative ─────────────────────────────────────────────────────────────

def _generate_narrative(data: dict) -> str:
    """Ask the LLM to write a 2-3 paragraph executive summary of the posture data."""
    llm = get_llm(temperature=0.3)

    prompt = f"""You are a CISO writing a daily security posture briefing for an engineering leadership audience.

Here is today's security data:

Open vulnerabilities:
  CRITICAL: {data["open_critical"]}
  HIGH: {data["open_high"]}
  MEDIUM: {data["open_medium"]}
  LOW: {data["open_low"]}
  Past SLA deadline: {data["past_sla_count"]}

Response metrics (last 30 days):
  Mean time to detect: {data["mttd_minutes"]} minutes
  Mean time to remediate: {data["mttr_days"]} days
  Trend vs previous 30 days: {data["trend_direction"]}

Team exposure (open findings per team):
{json.dumps(data["team_exposure"], indent=2)}

Compliance gaps (open findings in scope):
  PCI DSS: {data["compliance_gaps"]["pci_dss"]}
  HIPAA: {data["compliance_gaps"]["hipaa"]}
  SOC 2: {data["compliance_gaps"]["soc2"]}

Write a 2-3 paragraph executive summary. Be direct and specific. Mention which teams
need attention, call out any SLA breaches, highlight if the trend is positive or negative.
Do not use bullet points. Write in plain paragraphs suitable for a Slack message or email.
Do not include a subject line or greeting — just the body paragraphs.
"""
    response = llm.invoke(prompt)
    return response.content.strip()


# ── Persistence ───────────────────────────────────────────────────────────────

def _write_to_postgres(report_id: str, data: dict, narrative: str, conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO posture_reports (
                report_id, generated_at,
                open_critical, open_high, open_medium, open_low,
                past_sla_count, mttd_minutes, mttr_days,
                trend_direction, team_exposure, compliance_gaps,
                executive_summary
            ) VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                report_id,
                data["open_critical"], data["open_high"],
                data["open_medium"], data["open_low"],
                data["past_sla_count"], data["mttd_minutes"], data["mttr_days"],
                data["trend_direction"],
                json.dumps(data["team_exposure"]),
                json.dumps(data["compliance_gaps"]),
                narrative,
            ),
        )
    conn.commit()


def _write_to_minio(report_id: str, full_report: dict) -> None:
    try:
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"posture/{date_str}.json"
        data = json.dumps(full_report, indent=2, default=str).encode()
        client.put_object(
            "appsec-backups",
            key,
            data=__import__("io").BytesIO(data),
            length=len(data),
            content_type="application/json",
        )
        log.info("posture_report_archived", key=key)
    except Exception as e:
        log.warning("minio_write_failed", error=str(e))


# ── Public entrypoint ─────────────────────────────────────────────────────────

def run_posture_report() -> dict:
    """
    Generate and persist the daily posture report.

    Called by the scheduler (APScheduler cron) at 06:00 UTC.
    Can also be called directly for testing.

    Returns the full report dict.
    """
    now = datetime.now(timezone.utc)
    report_id = f"posture-{now.strftime('%Y-%m-%d')}"

    log.info("posture_report_started", report_id=report_id)

    conn = psycopg2.connect(POSTGRES_URL)
    try:
        data = _fetch_posture_data(conn)
        narrative = _generate_narrative(data)

        full_report = {
            "report_id": report_id,
            "generated_at": now.isoformat(),
            **data,
            "executive_summary": narrative,
        }

        _write_to_postgres(report_id, data, narrative, conn)
    finally:
        conn.close()

    _write_to_minio(report_id, full_report)

    log.info(
        "posture_report_complete",
        report_id=report_id,
        open_critical=data["open_critical"],
        trend=data["trend_direction"],
    )

    return full_report


# ── Scheduler entry ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run as a standalone process with APScheduler.
    Triggers at 06:00 UTC daily, and once immediately on startup.

    Usage:
        python agents/posture/agent.py
    """
    import time
    from apscheduler.schedulers.blocking import BlockingScheduler

    logging.basicConfig(level=logging.INFO)

    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(run_posture_report, "cron", hour=6, minute=0)

    log.info("posture_scheduler_started", schedule="06:00 UTC daily")

    run_posture_report()

    scheduler.start()
