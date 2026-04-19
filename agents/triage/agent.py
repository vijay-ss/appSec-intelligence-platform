"""
Vulnerability Triage Agent
===========================
LangGraph agent that triages VulnerabilityMatchEvents consumed from Kafka.

Node sequence (all deterministic except the final synthesis step):
  1. retrieve_cve_context     — RAG: cve_descriptions + exploit_reports
  2. fetch_affected_files     — GitHub API: files importing the vulnerable package
  3. assess_exploitability    — LLM: is the vulnerable code path actually called?
  4. fetch_remediation_path   — OSV query + deps.dev lookup
  5. generate_triage_report   — LLM synthesis over gathered evidence → TriageReport

The LLM is only called in steps 3 and 5. Steps 1, 2, and 4 are deterministic
tool calls. This makes a 7B local model viable — it reasons over pre-gathered
evidence rather than from general knowledge.
"""
import json
import os
from datetime import datetime, timezone, timedelta
from typing import TypedDict, Optional
from uuid import uuid4

from langgraph.graph import StateGraph, END
import structlog

from agents.llm_provider import get_llm
from agents.rag.retriever import retrieve
from agents.tools.github import fetch_file
from agents.tools.osv import query_osv
from agents.tools.deps_dev import lookup_deps_dev
from agents.tools.service_registry import get_service_metadata

log = structlog.get_logger()


class TriageState(TypedDict):
    match_event: dict
    
    cve_context: Optional[str]
    affected_files: list[dict]
    remediation_data: Optional[dict]
    service_metadata: Optional[dict]

    exploitability_verdict: Optional[str]
    exploitability_rationale: Optional[str]

    triage_report: Optional[dict]
    should_alert: bool


def retrieve_cve_context(state: TriageState) -> TriageState:
    """RAG: retrieve CVE descriptions and exploit reports from Qdrant."""
    match = state["match_event"]
    cve_id = match.get("cve_id", "")
    package = match.get("matched_package", "")

    query = f"{cve_id} {package} vulnerability exploit"
    docs = retrieve(query, collections=["cve_descriptions", "exploit_reports"], top_k=5)
    context = "\n\n".join(d.get("content", "") for d in docs)

    log.info("cve_context_retrieved", cve_id=cve_id, docs_found=len(docs))
    return {**state, "cve_context": context}


def fetch_affected_files(state: TriageState) -> TriageState:
    """
    GitHub API: fetch source files in the affected service that import the vulnerable package.
    service_id is the repo name (e.g. "psf/requests") for real services,
    or mapped to a repo via service registry for synthetic services.
    """
    match = state["match_event"]
    service_id = match.get("service_id", "")
    package = match.get("matched_package", "")

    files = []
    try:
        meta = get_service_metadata(service_id)
        repo = meta.get("repo", service_id)
        files = fetch_file(repo=repo, package_name=package)
    except Exception as e:
        log.warning("fetch_affected_files_failed", error=str(e), service_id=service_id)

    return {**state, "affected_files": files, "service_metadata": meta}


def assess_exploitability(state: TriageState) -> TriageState:
    """LLM node: determine if the vulnerable code path is actually reachable."""
    llm = get_llm(temperature=0.0)

    files_text = "\n\n".join(
        f"### {f['path']}\n```\n{f['content'][:2000]}\n```"
        for f in state.get("affected_files", [])
    ) or "No source files available."

    prompt = f"""You are a senior application security engineer.

CVE context:
{state.get('cve_context', 'Not available')}

Source files in the affected service that import the vulnerable package:
{files_text}

Task: Determine whether the vulnerable code path is actually called in these files.

Respond with a JSON object only:
{{
  "verdict": "CONFIRMED" | "LIKELY" | "UNLIKELY" | "NOT_AFFECTED",
  "rationale": "one paragraph explanation citing specific file and line evidence",
  "vulnerable_locations": [
    {{"file_path": "...", "line_number": null, "function_name": "...", "snippet": "..."}}
  ]
}}"""

    try:
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        parsed = json.loads(content)
        verdict = parsed.get("verdict", "UNLIKELY")
        rationale = parsed.get("rationale", "")
    except Exception as e:
        log.warning("exploitability_assessment_failed", error=str(e))
        verdict = "UNLIKELY"
        rationale = "Assessment failed — defaulting to UNLIKELY."

    return {
        **state,
        "exploitability_verdict": verdict,
        "exploitability_rationale": rationale,
    }


def check_not_affected(state: TriageState) -> str:
    """Routing function: skip full triage if NOT_AFFECTED."""
    if state.get("exploitability_verdict") == "NOT_AFFECTED":
        return "end"
    return "continue"


def fetch_remediation_path(state: TriageState) -> TriageState:
    """Deterministic: query OSV and deps.dev for safe version and compatibility."""
    match = state["match_event"]
    package = match.get("matched_package", "")
    version = match.get("matched_version", "")
    ecosystem = match.get("ecosystem", "")

    remediation = {}
    try:
        osv_data = query_osv(package=package, version=version, ecosystem=ecosystem)
        deps_data = lookup_deps_dev(package=package, version=version, ecosystem=ecosystem)
        remediation = {**osv_data, **deps_data}
    except Exception as e:
        log.warning("remediation_fetch_failed", error=str(e))

    return {**state, "remediation_data": remediation}


def generate_triage_report(state: TriageState) -> TriageState:
    """LLM synthesis: produce the final TriageReport from all gathered evidence."""
    llm = get_llm(temperature=0.0)
    match = state["match_event"]
    meta = state.get("service_metadata", {})
    remediation = state.get("remediation_data", {})

    prompt = f"""You are a senior application security engineer producing a triage report.

Evidence gathered:
- CVE ID: {match.get('cve_id')}
- Package: {match.get('matched_package')} {match.get('matched_version')}
- Ecosystem: {match.get('ecosystem')}
- Service: {match.get('service_id')}
- Service team: {meta.get('team', 'unknown')}
- Customer-facing: {meta.get('is_customer_facing', False)}
- Compliance scope: PCI={meta.get('pci_scope')}, HIPAA={meta.get('hipaa_scope')}, SOC2={meta.get('soc2_scope')}
- Exploitability verdict: {state.get('exploitability_verdict')}
- Exploitability rationale: {state.get('exploitability_rationale')}
- Safe version: {remediation.get('safe_version', 'unknown')}
- Breaking change: {remediation.get('is_breaking_change', False)}

CVE context:
{state.get('cve_context', 'Not available')}

Produce a triage report as a JSON object matching this schema exactly:
{{
  "remediation_action": "exact command e.g. pip install requests==2.32.1",
  "safe_version": "...",
  "is_breaking_change": false,
  "estimated_effort_hours": 0.5,
  "compatibility_notes": "...",
  "blast_radius_rationale": "...",
  "compliance_controls_at_risk": ["PCI DSS Req 6.3.3"],
  "downstream_services_at_risk": [],
  "confidence_score": 0.85
}}

Output JSON only. No preamble."""

    try:
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        llm_output = json.loads(content)
    except Exception as e:
        log.warning("triage_report_generation_failed", error=str(e))
        llm_output = {
            "remediation_action": f"Upgrade {match.get('matched_package')}",
            "confidence_score": 0.1,
        }

    sla_hours = {"CRITICAL": 4, "HIGH": 24, "MEDIUM": 168, "LOW": 720}
    tier = match.get("blast_radius_tier", "LOW")

    report = {
        "report_id": str(uuid4()),
        "cve_id": match.get("cve_id"),
        "service_id": match.get("service_id"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "exploitability_verdict": state.get("exploitability_verdict"),
        "exploitability_rationale": state.get("exploitability_rationale"),
        "blast_radius_tier": tier,
        "sla_deadline": (
            datetime.now(timezone.utc) + timedelta(hours=sla_hours.get(tier, 720))
        ).isoformat(),
        "assigned_team": meta.get("team", "unknown"),
        "llm_provider": os.getenv("LLM_PROVIDER", "ollama"),
        **llm_output,
    }

    return {**state, "triage_report": report, "should_alert": True}


def build_triage_graph() -> StateGraph:
    graph = StateGraph(TriageState)

    graph.add_node("retrieve_cve_context", retrieve_cve_context)
    graph.add_node("fetch_affected_files", fetch_affected_files)
    graph.add_node("assess_exploitability", assess_exploitability)
    graph.add_node("fetch_remediation_path", fetch_remediation_path)
    graph.add_node("generate_triage_report", generate_triage_report)

    graph.set_entry_point("retrieve_cve_context")
    graph.add_edge("retrieve_cve_context", "fetch_affected_files")
    graph.add_edge("fetch_affected_files", "assess_exploitability")
    graph.add_conditional_edges(
        "assess_exploitability",
        check_not_affected,
        {"end": END, "continue": "fetch_remediation_path"},
    )
    graph.add_edge("fetch_remediation_path", "generate_triage_report")
    graph.add_edge("generate_triage_report", END)

    return graph.compile()


triage_graph = build_triage_graph()
