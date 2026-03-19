"""
Named demo scenarios for the synthetic generator.
Each scenario returns a list of events to publish to Kafka.

Fire via: curl -X POST http://localhost:8090/scenario -d '{"scenario": "critical_rce"}'
Or:       make scenario SCENARIO=critical_rce
"""
import uuid
from datetime import datetime, timezone


def _dep_event(service_id: str, ecosystem: str, package: str, from_v: str, to_v: str) -> dict:
    return {
        "_topic": "deps.changes",
        "event_id": str(uuid.uuid4()),
        "source": "synthetic",
        "repo": service_id,
        "service_id": service_id,
        "pr_number": 9900,
        "author": "dependabot[bot]",
        "ecosystem": ecosystem,
        "manifest_file": "requirements.txt" if ecosystem == "pypi" else "package.json",
        "added": [],
        "removed": [],
        "updated": [{"package": package, "from_version": from_v, "to_version": to_v}],
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }


def _pin_event(service_id: str, ecosystem: str, package: str, version: str) -> dict:
    """Add a package at a specific (potentially vulnerable) version."""
    ev = _dep_event(service_id, ecosystem, package, "0.0.0", version)
    ev["added"] = [{"package": package, "version": version}]
    ev["updated"] = []
    return ev


# ── Scenario definitions ──────────────────────────────────────────────────────

def critical_rce():
    """
    RCE CVE in requests < 2.32.0 affecting 3 customer-facing PCI services.
    Expected outcome: 3 CRITICAL triage reports, Slack alerts to payments team.
    """
    return [
        _pin_event("checkout-api", "pypi", "requests", "2.28.0"),
        _pin_event("payment-processor", "pypi", "requests", "2.28.0"),
        _pin_event("auth-service", "pypi", "requests", "2.28.0"),
    ]


def mass_exposure():
    """
    cryptography < 42.0.4 affecting 8 services across 4 teams.
    Expected outcome: demonstrates blast radius scoring and team routing.
    """
    services = [
        "checkout-api", "auth-service", "user-api",
        "data-pipeline", "log-aggregator", "notification-worker",
        "secrets-manager", "fraud-detector",
    ]
    return [_pin_event(svc, "pypi", "cryptography", "41.0.0") for svc in services]


def supply_chain_attack():
    """
    PR adding PyYAML==5.3.1 (known vulnerable to arbitrary code exec).
    Expected outcome: PR Risk Agent posts BLOCK verdict before merge.
    """
    return [_pin_event("checkout-api", "pypi", "PyYAML", "5.3.1")]


def log4shell_redux():
    """
    Log4j 1.2.17 + Spring4Shell in legacy Java service.
    Expected outcome: demonstrates Maven ecosystem and multi-CVE detection.
    """
    return [
        _pin_event("legacy-billing", "maven", "log4j:log4j", "1.2.17"),
        _pin_event("legacy-billing", "maven", "org.springframework:spring-webmvc", "5.3.0"),
        _pin_event("document-processor", "maven", "log4j:log4j", "1.2.17"),
    ]


def safe_upgrade_wave():
    """
    10 services upgrade requests to the safe version 2.32.1.
    Expected outcome: no alerts fire — validates correct non-firing behaviour.
    """
    services = [
        "checkout-api", "payment-processor", "auth-service", "user-api",
        "data-pipeline", "log-aggregator", "notification-worker",
        "fraud-detector", "billing-scheduler", "feature-store-api",
    ]
    return [_dep_event(svc, "pypi", "requests", "2.28.0", "2.32.1") for svc in services]


def pr_risk_safe():
    """
    PR adding httpx==0.27.0 (no known CVEs at time of writing).
    Expected outcome: PR Risk Agent posts APPROVE verdict.
    """
    return [_pin_event("checkout-api", "pypi", "httpx", "0.27.0")]


SCENARIOS = {
    "critical_rce":        critical_rce,
    "mass_exposure":        mass_exposure,
    "supply_chain_attack":  supply_chain_attack,
    "log4shell_redux":      log4shell_redux,
    "safe_upgrade_wave":    safe_upgrade_wave,
    "pr_risk_safe":         pr_risk_safe,
}
