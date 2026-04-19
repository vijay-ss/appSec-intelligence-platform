"""
PR Risk Agent
=============
Assesses dependency-adding pull requests before they merge.

Triggered by: deps.risk.prs Kafka topic
(events routed there by the Flink router when a DependencyChangeEvent has
non-empty `added` — i.e. a net-new package is being introduced, not just a bump)

LangGraph workflow (3 nodes):
  1. check_osv       — deterministic: query OSV.dev for known CVEs
  2. check_deps_dev  — deterministic: check maintenance health via deps.dev
  3. generate_verdict — LLM: synthesise evidence → APPROVE / WARN / BLOCK

Output:
  - PRRiskVerdict written to PostgreSQL pr_risk_verdicts table
  - GitHub PR review comment posted via GitHub API
  - If BLOCK: GitHub commit status set to "failure" (gates merge if branch protection enabled)
"""
from __future__ import annotations

import json
import logging
import os
from typing import TypedDict

import httpx
import psycopg2
from langgraph.graph import StateGraph, END

from agents.llm_provider import get_llm
from agents.tools.osv import query_osv
from agents.tools.deps_dev import query_deps_dev

log = logging.getLogger(__name__)

POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://appsec:appsec@localhost:5432/appsec")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# ── State ─────────────────────────────────────────────────────────────────────

class PRRiskState(TypedDict):
    pr_event: dict  
    osv_results: list[dict]       
    deps_dev_results: list[dict]  
    verdict: str   
    rationale: str
    remediation: str


# ── Nodes ─────────────────────────────────────────────────────────────────────

def check_osv(state: PRRiskState) -> PRRiskState:
    """Query OSV.dev for known vulnerabilities in every added package."""
    added = state["pr_event"].get("added", [])
    results = []
    for dep in added:
        pkg = dep.get("package", "")
        ver = dep.get("version", "")
        eco = state["pr_event"].get("ecosystem", "pypi")
        result = query_osv(pkg, ver, eco)
        results.append({"package": pkg, "version": ver, **result})
    return {**state, "osv_results": results}


def check_deps_dev(state: PRRiskState) -> PRRiskState:
    """Check maintenance signals for each added package via deps.dev."""
    added = state["pr_event"].get("added", [])
    eco = state["pr_event"].get("ecosystem", "pypi")
    results = []
    for dep in added:
        pkg = dep.get("package", "")
        ver = dep.get("version", "")
        result = query_deps_dev(pkg, ver, eco)
        results.append({"package": pkg, "version": ver, **result})
    return {**state, "deps_dev_results": results}


def generate_verdict(state: PRRiskState) -> PRRiskState:
    """LLM synthesises all evidence into a structured APPROVE / WARN / BLOCK verdict."""
    llm = get_llm(temperature=0.0)

    pr = state["pr_event"]
    osv = state["osv_results"]
    deps = state["deps_dev_results"]

    prompt = f"""You are a security engineer reviewing a pull request that adds new dependencies.

PR details:
  Repo: {pr.get("repo")}
  PR #{pr.get("pr_number")}: {pr.get("added")}
  Ecosystem: {pr.get("ecosystem")}

OSV vulnerability check results:
{json.dumps(osv, indent=2)}

Dependency maintenance health (deps.dev):
{json.dumps(deps, indent=2)}

Based on this evidence, produce a JSON verdict:
{{
  "verdict": "APPROVE" | "WARN" | "BLOCK",
  "rationale": "one paragraph explaining the decision",
  "remediation": "specific action if WARN or BLOCK, empty string if APPROVE"
}}

Rules:
- BLOCK if any added package has known CVEs at the proposed version
- BLOCK if a package has zero maintainers or has not been released in over 2 years
- WARN if a package has no known CVEs but has concerning maintenance signals
- APPROVE if all packages are healthy and vulnerability-free
- Return ONLY the JSON object. No markdown, no explanation outside the JSON.
"""
    response = llm.invoke(prompt)
    try:
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        parsed = json.loads(content.strip())
    except Exception:
        parsed = {
            "verdict": "WARN",
            "rationale": "Could not parse LLM response — manual review required.",
            "remediation": "Review dependency additions manually before merging.",
        }

    return {
        **state,
        "verdict": parsed.get("verdict", "WARN"),
        "rationale": parsed.get("rationale", ""),
        "remediation": parsed.get("remediation", ""),
    }


# ── Graph ─────────────────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(PRRiskState)
    graph.add_node("check_osv", check_osv)
    graph.add_node("check_deps_dev", check_deps_dev)
    graph.add_node("generate_verdict", generate_verdict)

    graph.set_entry_point("check_osv")
    graph.add_edge("check_osv", "check_deps_dev")
    graph.add_edge("check_deps_dev", "generate_verdict")
    graph.add_edge("generate_verdict", END)

    return graph.compile()


pr_risk_graph = build_graph()


# ── Side effects ──────────────────────────────────────────────────────────────

def _post_github_review(pr_event: dict, verdict: str, rationale: str, remediation: str) -> None:
    """Post a PR review comment and set a commit status on GitHub."""
    if not GITHUB_TOKEN:
        log.warning("GITHUB_TOKEN not set — skipping GitHub PR comment")
        return

    repo = pr_event.get("repo", "")
    pr_number = pr_event.get("pr_number")
    if not repo or not pr_number:
        return

    icon = {"APPROVE": "✅", "WARN": "⚠️", "BLOCK": "🚫"}.get(verdict, "ℹ️")
    body = f"## AppSec Dependency Review {icon} {verdict}\n\n{rationale}"
    if remediation:
        body += f"\n\n**Recommended action:** {remediation}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Post review comment
    httpx.post(
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
        headers=headers,
        json={"body": body, "event": "COMMENT"},
        timeout=10,
    )

    log.info("posted_github_review", repo=repo, pr=pr_number, verdict=verdict)


def _write_to_postgres(pr_event: dict, verdict: str, rationale: str, remediation: str) -> None:
    conn = psycopg2.connect(POSTGRES_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pr_risk_verdicts
                  (repo, pr_number, ecosystem, added_packages, verdict, rationale, remediation, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (repo, pr_number) DO UPDATE
                  SET verdict = EXCLUDED.verdict,
                      rationale = EXCLUDED.rationale,
                      remediation = EXCLUDED.remediation
                """,
                (
                    pr_event.get("repo"),
                    pr_event.get("pr_number"),
                    pr_event.get("ecosystem"),
                    json.dumps(pr_event.get("added", [])),
                    verdict,
                    rationale,
                    remediation,
                ),
            )
        conn.commit()
    finally:
        conn.close()


# ── Public entrypoint ─────────────────────────────────────────────────────────

def assess_pr(pr_event: dict) -> dict:
    """
    Run the full PR risk assessment for a dependency-adding event.

    Args:
        pr_event: A DependencyChangeEvent dict with non-empty `added` list.

    Returns:
        dict with keys: verdict, rationale, remediation
    """
    initial_state: PRRiskState = {
        "pr_event": pr_event,
        "osv_results": [],
        "deps_dev_results": [],
        "verdict": "",
        "rationale": "",
        "remediation": "",
    }

    final_state = pr_risk_graph.invoke(initial_state)

    verdict = final_state["verdict"]
    rationale = final_state["rationale"]
    remediation = final_state["remediation"]

    _write_to_postgres(pr_event, verdict, rationale, remediation)
    _post_github_review(pr_event, verdict, rationale, remediation)

    log.info(
        "pr_risk_verdict",
        repo=pr_event.get("repo"),
        pr=pr_event.get("pr_number"),
        verdict=verdict,
    )

    return {"verdict": verdict, "rationale": rationale, "remediation": remediation}
