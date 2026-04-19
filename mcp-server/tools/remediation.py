"""MCP remediation tool."""
from agents.tools.osv import query_osv
from agents.tools.deps_dev import lookup_deps_dev


def get_remediation_path(package: str, version: str, ecosystem: str) -> dict:
    osv = query_osv(package=package, version=version, ecosystem=ecosystem)
    deps = lookup_deps_dev(package=package, version=version, ecosystem=ecosystem)
    return {"package": package, "installed_version": version, **osv, **deps}
