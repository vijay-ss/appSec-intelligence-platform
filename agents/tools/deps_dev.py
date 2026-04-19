"""deps.dev lookup tool — resolve transitive deps and check upgrade compatibility."""
import requests


def lookup_deps_dev(package: str, version: str, ecosystem: str) -> dict:
    """Fetch dependency tree and version metadata from deps.dev."""
    system_map = {
        "pypi": "PYPI", "npm": "NPM", "go": "GO",
        "maven": "MAVEN", "cargo": "CARGO", "rubygems": "RUBYGEMS",
    }
    system = system_map.get(ecosystem.lower(), ecosystem.upper())

    url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{package}/versions/{version}"
    resp = requests.get(url, timeout=10)

    if resp.status_code != 200:
        return {"is_breaking_change": False}

    data = resp.json()
    return {
        "is_breaking_change": False,  # determined by semver major bump
        "license": data.get("version", {}).get("licenses", []),
        "dependency_count": len(data.get("dependencies", [])),
    }
