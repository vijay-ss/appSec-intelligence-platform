"""
Triage Agent Consumer — consumes CRITICAL and HIGH match events from Kafka
and runs each through the triage agent graph.
"""
import json
import os

import psycopg2
import psycopg2.extras
import structlog
from confluent_kafka import Consumer, KafkaError

from agents.triage.agent import triage_graph
from appsec_shared.logging import configure_logging

log = configure_logging("triage-consumer")


def run():
    consumer = Consumer({
        "bootstrap.servers": os.getenv("KAFKA_BROKERS", "localhost:9092"),
        "group.id": "triage-agent",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    consumer.subscribe(["vuln.matches.critical", "vuln.matches.high"])
    
    conn = psycopg2.connect(os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec"))
    
    log.info("triage consumer started", topics=["vuln.matches.critical", "vuln.matches.high"])
    
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("kafka error", error=str(msg.error()))
                continue
            
            try:
                match_event = json.loads(msg.value().decode("utf-8"))
                log.info(
                    "processing match",
                    cve_id=match_event.get("cve_id"),
                    service_id=match_event.get("service_id")
                )
                
                result = triage_graph.invoke({"match_event": match_event, "affected_files": [], "should_alert": False})
                report = result.get("triage_report")
                
                if report:
                    _save_report(conn, report)
                    log.info("triage report saved", report_id=report.get("report_id"))
                
                consumer.commit(msg)

            except Exception as e:
                log.error("triage processing failed", error=str(e), exc_info=True)
    
    finally:
        consumer.close()
        conn.close()


def _save_report(conn, report: dict):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO triage_reports (
                report_id, match_id, cve_id, service_id,
                exploitability, exploitability_verdict, exploitability_rationale,
                blast_radius_tier, blast_radius_rationale,
                remediation_action, is_breaking_change,
                estimated_effort_hours, confidence_score, sources_cited,
                llm_provider, generated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (report_id) DO NOTHING
        """, (
            report.get("report_id"),
            report.get("match_id"),
            report.get("cve_id"),
            report.get("service_id"),
            report.get("exploitability_verdict"),
            report.get("exploitability_verdict"),
            report.get("exploitability_rationale"),
            report.get("blast_radius_tier"),
            report.get("blast_radius_rationale"),
            report.get("remediation_action"),
            report.get("is_breaking_change", False),
            report.get("estimated_effort_hours", 0.5),
            report.get("confidence_score", 0.0),
            json.dumps(report.get("sources_cited", [])),
            report.get("llm_provider", ""),
            report.get("generated_at"),
        ))
    conn.commit()


if __name__ == "__main__":
    run()
