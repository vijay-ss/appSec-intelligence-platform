"""OSV.dev query tool — fetch safe version and affected version list."""
import requests


def query_osv(package: str, version: str, ecosystem: str) -> dict:
    """Query OSV.dev for vulnerability details and safe version ranges."""
    ecosystem_map = {
        "pypi": "PyPI", "npm": "npm", "go": "Go",
        "maven": "Maven", "cargo": "crates.io", "rubygems": "RubyGems",
    }
    osv_eco = ecosystem_map.get(ecosystem.lower(), ecosystem)

    resp = requests.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": package, "ecosystem": osv_eco}},
        timeout=10,
    )

    if resp.status_code != 200:
        return {}

    vulns = resp.json().get("vulns", [])
    safe_version = None

    for vuln in vulns:
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                if r.get("type") == "ECOSYSTEM":
                    for event in r.get("events", []):
                        if "fixed" in event:
                            safe_version = event["fixed"]

    return {"safe_version": safe_version, "vuln_count": len(vulns)}