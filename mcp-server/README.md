# MCP Server

A query layer that exposes the platform's security intelligence through the [Model Context Protocol](https://modelcontextprotocol.io/). Any MCP-compatible client — VS Code with Cline, Claude Desktop, or a custom integration — can call these 9 tools in natural language.

The server does no AI reasoning. It translates MCP tool calls into PostgreSQL queries and Qdrant searches. All intelligence is produced upstream by the agents.

---

## Running in Docker

### Start the MCP server

```bash
# Start infrastructure first (postgres, qdrant, redis are required)
make infra-up

# Then start the MCP server
docker compose -f infrastructure/docker-compose.yml up -d mcp-server
```

Or as part of the full stack:

```bash
make up          # starts everything including the MCP server
make agents-up   # starts agents + MCP server after infra-up
```

### Watch the logs

```bash
make logs s=mcp-server

# Directly
docker compose -f infrastructure/docker-compose.yml logs -f mcp-server
```

### Rebuild after code changes

```bash
make rebuild s=mcp-server
```

---

## Connecting VS Code + Cline (using the Docker container)

The MCP server uses stdio transport — Cline launches it as a subprocess. To run it from the Docker container, configure Cline to use `docker exec`:

Create `.vscode/cline_mcp_config.json` in the project root:

```json
{
  "mcpServers": {
    "appsec-intelligence": {
      "command": "docker",
      "args": [
        "compose",
        "-f", "infrastructure/docker-compose.yml",
        "exec", "-T", "mcp-server",
        "python", "mcp-server/server.py"
      ]
    }
  }
}
```

The MCP server container must be running (`make up` or `make agents-up`) before Cline can connect.

### Alternatively — connect directly to the running process

If you prefer to let Cline start the MCP server directly on your machine (bypassing Docker for this one service):

```bash
# Start dependencies in Docker
docker compose -f infrastructure/docker-compose.yml up -d postgres qdrant redis

# Install dependencies locally
pip install -r mcp-server/requirements.txt
pip install -e ./shared
```

Then configure Cline:

```json
{
  "mcpServers": {
    "appsec-intelligence": {
      "command": "python",
      "args": ["mcp-server/server.py"],
      "env": {
        "POSTGRES_URL": "postgresql://appsec:appsec@localhost:5432/appsec",
        "QDRANT_HOST": "localhost",
        "QDRANT_PORT": "6333",
        "REDIS_URL": "redis://localhost:6379"
      }
    }
  }
}
```

### Example queries in VS Code

Once connected, invoke tools naturally in a Cline conversation:

```
"Which services have critical vulnerabilities with missed SLA deadlines?"
"Show me the full triage report for CVE-2024-35195"
"What compliance controls are at risk for the payments team?"
"Is there a safe upgrade path for requests 2.28.0?"
```

---

## Running without Docker (optional)

```bash
docker compose -f infrastructure/docker-compose.yml up -d postgres qdrant redis

pip install -r mcp-server/requirements.txt
pip install -e ./shared

export POSTGRES_URL=postgresql://appsec:appsec@localhost:5432/appsec
export QDRANT_HOST=localhost
export REDIS_URL=redis://localhost:6379

python mcp-server/server.py
```

---

## Environment variables

| Variable | Default (in container) | Description |
|---|---|---|
| `POSTGRES_URL` | `postgresql://appsec:appsec@postgres:5432/appsec` | `postgres` in Docker, `localhost` from host |
| `QDRANT_HOST` | `qdrant` | `qdrant` in Docker, `localhost` from host |
| `QDRANT_PORT` | `6333` | — |
| `REDIS_URL` | `redis://redis:6379` | `redis` in Docker, `localhost` from host |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | For the RAG retriever's embedding calls |
| `EMBEDDING_PROVIDER` | `ollama` | `ollama` or `openai` |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model for semantic search |

---

## Tools

### `get_vulnerability_exposure`

Returns all open vulnerability matches, optionally filtered by service. Sorted by blast radius tier then SLA deadline.

**Input:** `{ "service_id": "checkout-api" }` *(optional)*

---

### `get_cve_details`

Returns the full triage report for a CVE — exploitability verdict, code locations, blast radius rationale, exact remediation command.

**Input:** `{ "cve_id": "CVE-2024-35195" }`

---

### `search_vulnerabilities`

Semantic search over all triaged vulnerability reports using Qdrant.

**Input:** `{ "query": "authentication bypass in customer-facing services" }`

---

### `get_remediation_path`

Returns the safe upgrade version and compatibility notes for a specific package version.

**Input:** `{ "package": "requests", "version": "2.28.0", "ecosystem": "pypi" }`

---

### `get_affected_services`

Lists all services affected by a specific CVE with blast radius tier and SLA status.

**Input:** `{ "cve_id": "CVE-2024-35195" }`

---

### `get_team_exposure`

All open vulnerabilities owned by a team, sorted by SLA urgency.

**Input:** `{ "team_name": "payments" }`

---

### `get_compliance_gaps`

Open vulnerabilities in services in scope for a specific compliance framework.

**Input:** `{ "framework": "pci_dss" }` *(options: `pci_dss`, `soc2`, `hipaa`, `iso27001`)*

---

### `get_security_posture_summary`

Most recent daily posture report with aggregate counts, trend direction, and LLM-generated executive narrative.

**Input:** None

---

### `get_dependency_graph`

Current live dependency snapshot for a service from Flink graph state.

**Input:** `{ "service_id": "checkout-api" }`

---

## Adding a new tool

1. Add a tool definition to `list_tools()` in `server.py`
2. Add a handler branch in `call_tool()` in `server.py`
3. Implement the query function in the appropriate file under `tools/`
4. Rebuild the container: `make rebuild s=mcp-server`
