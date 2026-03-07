<p align="center">
  <h1 align="center">🛡️ AgentAudit</h1>
  <p align="center">
    <strong>Security scanner for MCP (Model Context Protocol) servers</strong>
  </p>
  <p align="center">
    The only tool that actively stress-tests running MCP servers for vulnerabilities.
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#modules">Modules</a> •
    <a href="#ci-cd">CI/CD</a> •
    <a href="#sarif-output">SARIF</a>
  </p>
</p>

---

## Why AgentAudit?

MCP servers expose tools, resources, and prompts to AI agents — but **who audits the servers?**

Traditional security tools can't assess MCP-specific risks like tool poisoning, annotation trust violations, or SSRF through tool parameters. AgentAudit fills that gap with **5 specialized audit modules** that analyze both schema metadata (passive) and live server behavior (active).

```
  AgentAudit Security Report
  ──────────────────────────────────────────────────────────────

  Server: @modelcontextprotocol/server-filesystem v0.6.2
  Protocol: 2024-11-05
  Capabilities: 11 tools, 0 resources, 0 prompts
  Scan Duration: 1243ms

  ✓ Tool Permissions Analysis v1.0.0 (23ms)
     PASS  Tool exposure count — 11 tools exposed
     PASS  Tool descriptions present — All tools have descriptions
     WARN  Dangerous tools: write-operations — 5 tool(s) with write-operations patterns
     WARN  Schema constraints: edit_file — 1 parameter(s) with insufficient constraints
     PASS  Tool annotations present — All tools have annotations
     PASS  Annotation consistency — Tool annotations appear consistent
     PASS  Additional properties restricted — No tools allow additional properties

  ✓ Transport Security v1.0.0 (1ms)
     PASS  Server capability declaration
     PASS  Sampling capability
     PASS  Roots capability
     PASS  Dynamic tool registration
     PASS  Resource exposure
     PASS  Protocol version

  Security Score: 82/100 (Grade: B)
```

## Installation

```bash
# Run directly with npx
npx agentaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Or install globally
npm install -g agentaudit

# Or with Bun
bun install -g agentaudit
```

### Build from Source

```bash
git clone https://github.com/agentaudit/agentaudit.git
cd agentaudit
bun install
bun run build

# Or compile to standalone binary
bun run compile
./packages/cli/agentaudit --version
```

## Quick Start

### Scan an MCP Server

```bash
# Basic scan (passive modules only)
agentaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Full scan with active probing (SSRF detection)
agentaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --active

# JSON output for programmatic use
agentaudit scan -s "your-mcp-server" -f json

# SARIF output for GitHub Code Scanning
agentaudit scan -s "your-mcp-server" -f sarif -o report.sarif

# CI mode (no color, JSON output, non-zero exit on findings)
agentaudit scan -s "your-mcp-server" --ci

# Run specific modules only
agentaudit scan -s "your-mcp-server" -m tool-permissions transport-security

# Verbose output for debugging
agentaudit scan -s "your-mcp-server" -v
```

## Modules

AgentAudit ships with 5 audit modules:

### 🔐 Tool Permissions Analysis (`tool-permissions`) — Passive

Analyzes tool schemas for over-permissioning, dangerous patterns, and annotation trust issues.

| Check | What It Detects |
|---|---|
| TP-001 | Large tool surface (>20 tools) |
| TP-002 | Missing tool descriptions |
| TP-003 | Dangerous tool names (command execution, destructive ops, network access) |
| TP-004 | Missing input schemas |
| TP-005 | Unconstrained parameters (path traversal, injection, SSRF risks) |
| TP-006 | Missing annotations (readOnlyHint, destructiveHint) |
| TP-007 | Contradictory annotations (e.g., `delete_*` marked `readOnlyHint: true`) |
| TP-008 | `additionalProperties: true` allowing arbitrary input injection |

### 🌐 SSRF Detection (`ssrf-detection`) — Active

Probes tools with URL parameters using controlled SSRF payloads. Tests internal network access, cloud metadata endpoints (AWS/GCP/Azure), protocol smuggling, and IP encoding bypasses.

| Check | What It Detects |
|---|---|
| SSRF-001 | Tools accepting URL parameters |
| SSRF-010 | Successful SSRF probes (loopback, cloud metadata, protocol smuggling) |

**Severity escalation:** Cloud metadata access → CRITICAL, Internal network → HIGH, Protocol smuggling → HIGH

### 🔒 Transport Security (`transport-security`) — Passive

Analyzes server capability declarations and transport configuration.

| Check | What It Detects |
|---|---|
| TS-001 | Missing capability declarations |
| TS-002 | Sampling capability (server can request LLM completions) |
| TS-003 | Roots capability (filesystem path discovery) |
| TS-004 | Dynamic tool registration (tool poisoning / rug pull vector) |
| TS-005 | Sensitive resource exposure (env, secrets, credentials in URIs) |
| TS-006 | Unknown/non-standard protocol versions |

### 🧬 Schema Manipulation (`schema-manipulation`) — Passive

Detects tools that could be used for injection attacks through schema weaknesses.

### 🔍 Context Extraction (`context-extraction`) — Passive

Identifies tools and resources that could leak sensitive context or be used for data exfiltration.

## Scoring System

AgentAudit calculates a **0-100 security score** based on finding severity:

| Severity | Score Impact | Grade Scale |
|---|---|---|
| CRITICAL | -25 points | A: 90-100 |
| HIGH | -15 points | B: 80-89 |
| MEDIUM | -8 points | C: 70-79 |
| LOW | -3 points | D: 60-69 |
| INFO | 0 points | F: 0-59 |

Per-module impact is capped at 50 points to prevent a single noisy module from dominating the score.

## CI/CD

### GitHub Actions

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2

      - name: Install AgentAudit
        run: bun install -g agentaudit

      - name: Scan MCP Server
        run: agentaudit scan -s "your-mcp-server" --ci --accept -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | All checks passed |
| 1 | Warnings found |
| 2 | Failures found |
| 3 | Critical findings |
| 4 | Scan error |

## SARIF Output

AgentAudit can output results in [SARIF](https://sarifweb.azurewebsites.net/) format for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```bash
agentaudit scan -s "your-mcp-server" -f sarif -o report.sarif
```

SARIF reports include:
- Finding locations mapped to tool names
- Severity levels mapped to SARIF levels
- CWE IDs where applicable (e.g., CWE-918 for SSRF)
- Remediation guidance in each result

## Architecture

```
packages/cli/
├── src/
│   ├── index.ts              # CLI entrypoint (Commander.js)
│   ├── commands/
│   │   └── scan.ts           # Scan orchestration
│   ├── core/
│   │   ├── mcp-client.ts     # MCP client with stdio transport + pagination
│   │   ├── module-runner.ts  # Sequential module execution with error isolation
│   │   ├── reporter.ts       # Terminal (chalk) + JSON + SARIF output
│   │   ├── scorer.ts         # 0-100 security scoring with severity weights
│   │   ├── acceptance.ts     # User acceptance flow for active scanning
│   │   └── sarif.ts          # SARIF report generation
│   ├── modules/
│   │   ├── tool-permissions.ts      # Schema & annotation analysis
│   │   ├── ssrf-detection.ts        # Active SSRF probing
│   │   ├── transport-security.ts    # Transport & capability analysis
│   │   ├── schema-manipulation.ts   # Injection via schema weaknesses
│   │   └── context-extraction.ts    # Sensitive data leak detection
│   └── types/
│       ├── finding.ts        # Severity, CheckStatus, Finding, CheckResult
│       ├── module.ts         # AuditModule interface, ModuleContext
│       └── report.ts         # ToolInfo, ServerCapabilities, ScanReport
└── tests/
    ├── fixtures/             # Safe & vulnerable tool schemas
    ├── modules/              # Per-module unit tests
    └── core/                 # Core component tests
```

## Development

```bash
# Install dependencies
bun install

# Run in development mode
bun run dev -- scan -s "your-mcp-server"

# Run tests
bun test

# Type checking
bun run typecheck

# Build for distribution
bun run build

# Compile standalone binary
bun run compile
```

## License

Apache-2.0
