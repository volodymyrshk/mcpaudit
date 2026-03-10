<p align="center">
  <h1 align="center">🛡️ vs-mcpaudit</h1>
  <p align="center">
    <strong>security scanner for MCP (Model Context Protocol) servers</strong>
  </p>
  <p align="center">
    the only tool that actually stress-tests running mcp servers for vulnerabilities.
  </p>
  <p align="center">
    <a href="#installation">install</a> •
    <a href="#quick-start">quick start</a> •
    <a href="#modules">modules</a> •
    <a href="#ci-cd">ci/cd</a>
  </p>
</p>

---

## why vs-mcpaudit?

mcp servers expose tools, resources, and prompts to AI agents — but **who audits the servers??**

traditional security tools can't assess mcp-specific risks like tool poisoning, annotation trust violations, or ssrf through tool parameters. vs-mcpaudit fills that gap with **5 specialized audit modules** that analyze both schema metadata and live server behavior (yeah it actively probes things).

```
  vs-mcpaudit Security Report
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
npx vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Or install globally
npm install -g vs-mcpaudit

# Or with Bun
bun install -g vs-mcpaudit
```

### Build from Source

```bash
git clone https://github.com/vs-mcpaudit/vs-mcpaudit.git
cd vs-mcpaudit
bun install
bun run build

# Or compile to standalone binary
bun run compile
./packages/cli/vs-mcpaudit --version
```

## Quick Start

### Scan an MCP Server

```bash
# Basic scan (passive modules only)
vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Full scan with active probing (SSRF detection)
vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --active

# JSON output for programmatic use
vs-mcpaudit scan -s "your-mcp-server" -f json

# SARIF output for GitHub Code Scanning
vs-mcpaudit scan -s "your-mcp-server" -f sarif -o report.sarif

# CI mode (no color, JSON output, non-zero exit on findings)
vs-mcpaudit scan -s "your-mcp-server" --ci

# Run specific modules only
vs-mcpaudit scan -s "your-mcp-server" -m tool-permissions transport-security

# Verbose output for debugging
vs-mcpaudit scan -s "your-mcp-server" -v
```

## modules

vs-mcpaudit ships with 5 audit modules so far:

### 🔐 tool permissions analysis (`tool-permissions`) 

looks at tool schemas for over-permissioning, dangerous patterns, and annotation issues. tbh a lot of servers fail this one.

| check | what it detects |
|---|---|
| TP-001 | massive tool surface (>20 tools) |
| TP-002 | missing tool descriptions |
| TP-003 | dangerous tool names (command exec, destructive ops, network access) |
| TP-004 | missing input schemas |
| TP-005 | unconstrained parameters (path traversal, injection, ssrf risks) |
| TP-006 | missing annotations (readOnlyHint, etc) |
| TP-007 | contradictory annotations (e.g., `delete_*` marked `readOnlyHint: true`) |
| TP-008 | `additionalProperties: true` allowing arbitrary input injection |

### 🌐 ssrf detection (`ssrf-detection`) — active

probes tools with url parameters using controlled ssrf payloads. tests internal network access, cloud metadata endpoints, protocol smuggling, etc.

| check | what it detects |
|---|---|
| SSRF-001 | tools accepting url parameters |
| SSRF-010 | successful ssrf probes (loopback, metadata, protocol smuggling) |

**severity:** cloud metadata access → CRITICAL, internal network → HIGH, protocol smuggling → HIGH

### 🔒 transport security (`transport-security`) 

checks server capability declarations and transport config.

| check | what it detects |
|---|---|
| TS-001 | missing capability declarations |
| TS-002 | sampling capability (server can request LLM completions) |
| TS-003 | roots capability (filesystem path discovery) |
| TS-004 | dynamic tool registration (tool poisoning vector) |
| TS-005 | sensitive resource exposure (env, secrets in URIs) |
| TS-006 | weird/non-standard protocol versions |

### 🧬 schema manipulation (`schema-manipulation`) 

detects tools that could be used for injection attacks through schema weaknesses.

### 🔍 context extraction (`context-extraction`) 

identifies tools and resources that could leak sensitive context or be used for data exfiltration.

## Scoring System

vs-mcpaudit calculates a **0-100 security score** based on finding severity:

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

      - name: Install vs-mcpaudit
        run: bun install -g vs-mcpaudit

      - name: Scan MCP Server
        run: vs-mcpaudit scan -s "your-mcp-server" --ci --accept -o results.sarif

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

vs-mcpaudit can output results in [SARIF](https://sarifweb.azurewebsites.net/) format for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```bash
vs-mcpaudit scan -s "your-mcp-server" -f sarif -o report.sarif
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
