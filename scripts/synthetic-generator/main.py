"""
Synthetic Generator — demo data for the AppSec Intelligence Platform.

Three functions in one container:
  1. Registry seeder  — seeds PostgreSQL with 50 fictional services on startup
  2. Background hum   — emits realistic dep change events at ~2/second continuously
  3. Scenario trigger — HTTP endpoint to fire named demo scenarios on demand

Run via Docker Compose or directly:
  python main.py --mode hum
  python main.py --seed-only
  curl -X POST http://localhost:8090/scenario -d '{"scenario": "critical_rce"}'
"""
import argparse
import json
import logging
import os
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import psycopg2
import psycopg2.extras
from confluent_kafka import Producer

from registry import SERVICES
from scenarios import SCENARIOS


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:9092")
POSTGRES_URL  = os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")
HUM_RATE      = float(os.getenv("HUM_RATE", "2.0"))


def get_producer() -> Producer:
    return Producer({"bootstrap.servers": KAFKA_BROKERS})


def get_conn():
    return psycopg2.connect(POSTGRES_URL)


# ── Registry seeder ───────────────────────────────────────────────────────────

def seed_registry():
    """Seed PostgreSQL service_registry with the 50 synthetic services."""
    log.info("seeding service registry...")
    conn = get_conn()
    with conn.cursor() as cur:
        for svc in SERVICES:
            cur.execute("""
                INSERT INTO service_registry
                  (service_id, team, ecosystem, repo, is_customer_facing,
                   pci_scope, hipaa_scope, soc2_scope, pii_handler, description, code_owners)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (service_id) DO NOTHING
            """, (
                svc["service_id"], svc["team"], svc["ecosystem"],
                svc.get("repo", svc["service_id"]),
                svc["is_customer_facing"], svc["pci_scope"],
                svc["hipaa_scope"], svc["soc2_scope"], svc["pii_handler"],
                svc["description"], json.dumps(svc["code_owners"]),
            ))
    conn.commit()
    conn.close()
    log.info(f"seeded {len(SERVICES)} services into registry")


# ── Background hum ────────────────────────────────────────────────────────────

def hum(producer: Producer):
    """Emit realistic dependency change events continuously at HUM_RATE/second."""
    interval = 1.0 / HUM_RATE
    packages = [
        ("requests",          "pypi", "2.28.0",  "2.31.0"),
        ("urllib3",           "pypi", "1.26.14", "2.0.7"),
        ("cryptography",      "pypi", "41.0.0",  "42.0.5"),
        ("axios",             "npm",  "1.3.0",   "1.7.9"),
        ("lodash",            "npm",  "4.17.19", "4.17.21"),
        ("express",           "npm",  "4.18.1",  "4.18.3"),
        ("golang.org/x/net",  "go",   "0.15.0",  "0.23.0"),
    ]

    log_interval = int(os.getenv("HUM_LOG_INTERVAL", "50"))
    published = 0

    log.info(f"hum starting at {HUM_RATE} events/second (logging every {log_interval} events)")

    while True:
        svc = random.choice(SERVICES)
        pkg, eco, from_v, to_v = random.choice(packages)

        event = {
            "event_id":     str(uuid.uuid4()),
            "source":       "synthetic",
            "repo":         svc["service_id"],
            "service_id":   svc["service_id"],
            "pr_number":    random.randint(1000, 9999),
            "author":       "dependabot[bot]",
            "ecosystem":    eco,
            "manifest_file": "requirements.txt" if eco == "pypi" else "package.json",
            "added":        [],
            "removed":      [],
            "updated":      [{"package": pkg, "from_version": from_v, "to_version": to_v}],
            "occurred_at":  datetime.now(timezone.utc).isoformat(),
            "ingested_at":  datetime.now(timezone.utc).isoformat(),
        }

        producer.produce("deps.changes", key=svc["service_id"], value=json.dumps(event))
        producer.poll(0)
        published += 1

        if published % log_interval == 0:
            log.info(
                f"hum published={published} "
                f"last_pkg={pkg} {from_v}→{to_v} "
                f"service={svc['service_id']} eco={eco}"
            )

        time.sleep(interval)


# ── Scenario trigger ──────────────────────────────────────────────────────────

class ScenarioHandler(BaseHTTPRequestHandler):
    def __init__(self, producer, *args, **kwargs):
        self.producer = producer
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path == "/scenario":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            scenario_name = body.get("scenario", "")

            if scenario_name not in SCENARIOS:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"unknown scenario: {scenario_name}"}).encode())
                log.warning(f"unknown scenario requested: {scenario_name!r}")
                return

            events = SCENARIOS[scenario_name]()
            for event in events:
                topic = event.pop("_topic", "deps.changes")
                self.producer.produce(topic, key=event.get("service_id", ""), value=json.dumps(event))
            self.producer.flush()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"fired": scenario_name, "events": len(events)}).encode())
            log.info(f"scenario fired: {scenario_name} ({len(events)} events)")

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif self.path == "/scenarios":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"available": list(SCENARIOS.keys())}).encode())


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="hum", choices=["hum", "seed-only"])
    parser.add_argument("--seed-only", action="store_true")
    args = parser.parse_args()

    log.info(
        f"synthetic generator starting "
        f"brokers={KAFKA_BROKERS} "
        f"hum_rate={HUM_RATE} "
        f"mode={args.mode}"
    )

    if os.getenv("SEED_REGISTRY", "true").lower() == "true":
        seed_registry()

    if args.seed_only or args.mode == "seed-only":
        log.info("registry seeded — exiting (seed-only mode)")
        return

    producer = get_producer()
    log.info(f"kafka producer connected: brokers={KAFKA_BROKERS}")

    # Start scenario HTTP server in background thread
    server = HTTPServer(
        ("0.0.0.0", 8090),
        lambda *a, **kw: ScenarioHandler(producer, *a, **kw)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("scenario server listening on :8090")
    log.info(f"available scenarios: {list(SCENARIOS.keys())}")

    # Run background hum in main thread
    hum(producer)


if __name__ == "__main__":
    main()