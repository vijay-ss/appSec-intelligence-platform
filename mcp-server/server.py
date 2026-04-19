"""
AppSec Intelligence MCP Server
================================
Exposes 9 tools over the Model Context Protocol so any MCP-compatible client
(VS Code + Cline, Claude Desktop, etc.) can query live security intelligence.

The server is a thin query layer — no AI reasoning happens here.
All tools read from PostgreSQL and Qdrant (via the RAG retriever).

VS Code + Cline configuration (.vscode/cline_mcp_config.json):
{
  "mcpServers": {
    "appsec-intelligence": {
      "command": "python",
      "args": ["mcp-server/server.py"],
      "env": {
        "POSTGRES_URL": "postgresql://appsec:appsec@localhost:5432/appsec",
        "QDRANT_URL": "http://localhost:6333",
        "REDIS_URL": "redis://localhost:6379"
      }
    }
  }
}
"""
import json
import os

import psycopg2
import psycopg2.extras
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from mcp_server.tools.vulnerability import (
    get_vulnerability_exposure,
    get_cve_details,
    get_affected_services,
)
from mcp_server.tools.search import search_vulnerabilities
from mcp_server.tools.remediation import get_remediation_path
from mcp_server.tools.compliance import get_compliance_gaps
from mcp_server.tools.posture import (
    get_team_exposure,
    get_security_posture_summary,
    get_dependency_graph,
)

server = Server("appsec-intelligence")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="get_vulnerability_exposure",
            description="Get all open vulnerabilities for a service or across all services, with triage status and SLA deadlines.",
            inputSchema={"type": "object", "properties": {"service_id": {"type": "string", "description": "Optional service ID to filter by"}}, "required": []},
        ),
        types.Tool(
            name="get_cve_details",
            description="Get the full triage report for a CVE: exploitability verdict, blast radius, code locations, and remediation.",
            inputSchema={"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
        ),
        types.Tool(
            name="search_vulnerabilities",
            description="Semantic search over all triaged vulnerability reports. Example: 'critical Python CVEs this week'",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        ),
        types.Tool(
            name="get_remediation_path",
            description="Get the safest upgrade path for a package, including compatibility notes and effort estimate.",
            inputSchema={"type": "object", "properties": {"package": {"type": "string"}, "version": {"type": "string"}, "ecosystem": {"type": "string"}}, "required": ["package", "version", "ecosystem"]},
        ),
        types.Tool(
            name="get_affected_services",
            description="List all services affected by a CVE with blast radius scores and SLA status.",
            inputSchema={"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
        ),
        types.Tool(
            name="get_team_exposure",
            description="Get all open vulnerabilities owned by a team, sorted by SLA urgency.",
            inputSchema={"type": "object", "properties": {"team_name": {"type": "string"}}, "required": ["team_name"]},
        ),
        types.Tool(
            name="get_compliance_gaps",
            description="Get open vulnerabilities representing gaps in a compliance framework.",
            inputSchema={"type": "object", "properties": {"framework": {"type": "string", "enum": ["pci_dss", "soc2", "hipaa", "iso27001"]}}, "required": ["framework"]},
        ),
        types.Tool(
            name="get_security_posture_summary",
            description="Get the most recent daily security posture report with trend analysis.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="get_dependency_graph",
            description="Get the current dependency snapshot for a service from the Flink graph state.",
            inputSchema={"type": "object", "properties": {"service_id": {"type": "string"}}, "required": ["service_id"]},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "get_vulnerability_exposure":
            result = get_vulnerability_exposure(arguments.get("service_id"))
        elif name == "get_cve_details":
            result = get_cve_details(arguments["cve_id"])
        elif name == "search_vulnerabilities":
            result = search_vulnerabilities(arguments["query"])
        elif name == "get_remediation_path":
            result = get_remediation_path(arguments["package"], arguments["version"], arguments["ecosystem"])
        elif name == "get_affected_services":
            result = get_affected_services(arguments["cve_id"])
        elif name == "get_team_exposure":
            result = get_team_exposure(arguments["team_name"])
        elif name == "get_compliance_gaps":
            result = get_compliance_gaps(arguments["framework"])
        elif name == "get_security_posture_summary":
            result = get_security_posture_summary()
        elif name == "get_dependency_graph":
            result = get_dependency_graph(arguments["service_id"])
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as e:
        result = {"error": str(e)}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
