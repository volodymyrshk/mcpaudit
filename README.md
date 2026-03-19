<p align="center">
  <img src="https://img.shields.io/badge/Agent_Tool_Interface-Security_Scanner-blueviolet?style=for-the-badge" alt="Agent Tool Interface Security Scanner" />
</p>

# vs-mcpaudit

![](https://img.shields.io/badge/Bun-1.1%2B-orange?style=flat-square) ![](https://img.shields.io/badge/Node.js-20%2B-brightgreen?style=flat-square) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0) ![](https://img.shields.io/badge/Tests-283_passing-success?style=flat-square) ![](https://img.shields.io/badge/Checks-94-informational?style=flat-square)

Security scanner for **AI agent tool interfaces**. Connects to running MCP servers via stdio or HTTP, discovers tools/resources/prompts, runs 12 audit modules with 94 security checks, evaluates custom policy rules, and produces a scored report with actionable fix suggestions.

Built for security teams, platform engineers, and anyone shipping AI tool servers to production.

> **Why this matters:** AI agents are exploding. Tool integrations are everywhere. Almost nobody is auditing the security of tool execution surfaces. vs-mcpaudit fills that gap, starting with MCP and designed to expand to other agent tool interfaces.

---

## Quick Start

```bash
# Interactive wizard (just run with no args)
npx vs-mcpaudit

# Scan profiles — one flag replaces five
npx vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile quick
npx vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile standard
npx vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile enterprise
```

### Scan Profiles

| Profile | What it does | Speed |
|---------|-------------|-------|
| `quick` | Passive checks only (schema analysis, no server calls) | ~5s |
| `standard` | Passive + active probes (calls tools with test payloads) | ~30s |
| `enterprise` | Full suite: active + TUI dashboard + autofix + executive summary + compliance | ~60s |

> **Smart defaults:** When running in an interactive terminal, TUI dashboard, autofix suggestions, and executive summary are enabled automatically. Only `--active` requires explicit opt-in.

## Installation

```bash
# NPM
npm install -g vs-mcpaudit

# Bun
bun install -g vs-mcpaudit

# From source
git clone https://github.com/volodymyrshk/mcpaudit.git
cd mcpaudit && bun install && bun run build
```

---

## How It Works

```
┌──────────────┐     stdio/HTTP     ┌──────────────┐
│  vs-mcpaudit │ ─────────────────> │  MCP Server  │
│              │ <───────────────── │              │
│  12 modules  │   tools/list       │  Your server │
│  94 checks   │   tools/call       │              │
│  Scored 0-100│   resources/list   │              │
└──────────────┘                    └──────────────┘
```

1. **Connects** to your MCP server via stdio or streamable-http transport
2. **Discovers** all tools, resources, and prompts
3. **Runs passive modules** in parallel (schema analysis, no server calls)
4. **Runs active modules** sequentially (actually calls tools with adversarial inputs)
5. **Evaluates custom policy rules** (if `--rules` specified)
6. **Scores** results 0-100 with severity-weighted deductions
7. **Reports** findings with CWE mappings, compliance controls, and fix suggestions

---

## Audit Modules

### Passive Modules (no server calls)

| Module | Checks | What It Finds |
|--------|--------|---------------|
| **tool-permissions** | 4 | Over-permissioned schemas, unconstrained params, dangerous tool names, annotation contradictions |
| **transport-security** | 5 | Dynamic tool registration, sampling capability abuse, sensitive resource URIs, version anomalies |
| **schema-manipulation** | 4 | Prompt injection in descriptions, hidden instructions, schema validation bypass vectors |
| **context-extraction** | 4 | Data exfiltration chains, outbound sinks, environment context leaks |
| **secret-leak-detection** | 4 | Hardcoded API keys, tokens, passwords, and credentials in schemas |
| **resource-prompt-audit** | 4 | Resource access control gaps, prompt injection in prompt templates |
| **supply-chain-analysis** | 5 | Typosquatting server names, suspicious metadata, capability sprawl, version anomalies |

### Active Modules (calls tools with test payloads)

| Module | Checks | What It Finds |
|--------|--------|---------------|
| **ssrf-detection** | 3 | Loopback access, cloud metadata exposure (AWS/GCP/Azure), protocol smuggling |
| **active-fuzzer** | 9 | Command injection (CWE-78), path traversal (CWE-22), SQL injection (CWE-89), XSS (CWE-79), oversized input handling, unicode normalization, mutation-based bypass |
| **tool-shadowing** | 3 | Schema honesty violations, read-only annotation lies, undeclared parameter acceptance |
| **response-fingerprinting** | 3 | Non-deterministic responses, timing side channels, stateful behavior indicating hidden state |
| **auth-boundary-testing** | 3 | Cross-tool data leakage, privilege escalation via annotations, resource boundary violations |

> Active modules require the `--active` flag. They make real tool calls to your server.

---

## Custom Policy Rules (Rule DSL)

Define your own security policies in YAML or JSON. Rules are evaluated against the server's discovered capabilities and produce findings that integrate directly into the scan report and score.

```bash
vs-mcpaudit scan -s "..." --rules policy.yml
```

### Example: `policy.yml`

```yaml
rules:
  - id: POLICY-001
    name: "No shell execution tools"
    severity: CRITICAL
    message: "Shell execution tools are forbidden in production servers"
    remediation: "Remove or restrict shell/exec tools behind authentication"
    cweId: CWE-78
    match:
      tool_name: /exec|shell|bash|cmd|powershell/i

  - id: POLICY-002
    name: "Maximum tool count"
    severity: MEDIUM
    message: "Server exposes too many tools, increasing attack surface"
    match:
      tool_count: { gt: 20 }

  - id: POLICY-003
    name: "No secret resources"
    severity: HIGH
    message: "Resources with secret/credential URIs detected"
    match:
      resource_uri: /secret|password|credential|\.env/i

  - id: POLICY-004
    name: "Must expose a health check tool"
    severity: LOW
    message: "Production servers should have a health check tool"
    negate: true  # Fail when the match is NOT found
    match:
      tool_name: /health|ping|status/i

  - id: POLICY-005
    name: "No destructive tools without safeguards"
    severity: HIGH
    message: "Destructive tools must be reviewed"
    match:
      annotation:
        destructiveHint: true
```

### Match Conditions

| Condition | What it checks | Value type |
|-----------|---------------|------------|
| `tool_name` | Tool names | string or `/regex/flags` |
| `tool_description` | Tool descriptions (`null` = missing) | string, regex, or `null` |
| `resource_uri` | Resource URIs | string or regex |
| `prompt_name` | Prompt names | string or regex |
| `param_name` | Parameter names in tool schemas | string or regex |
| `tool_count` | Number of tools | `{ gt: N }` or `{ lt: N }` |
| `resource_count` | Number of resources | `{ gt: N }` or `{ lt: N }` |
| `prompt_count` | Number of prompts | `{ gt: N }` or `{ lt: N }` |
| `server_name` | Server name | string or regex |
| `server_version` | Server version | string or regex |
| `annotation` | Tool annotation values | `{ destructiveHint: true }` etc. |
| `schema_property` | Schema property names | string (deep search) |
| `capability` | Server capability keys | string |

Use `negate: true` to invert the rule: fail when the match is **not** found (useful for "must have X" policies).

---

## Output & Reporting

### Formats

```bash
# Rich terminal output (default)
vs-mcpaudit scan -s "..." --active

# JSON for scripting
vs-mcpaudit scan -s "..." -f json -o report.json

# HTML report (dark-mode, SVG score ring)
vs-mcpaudit scan -s "..." -f html -o report.html

# Markdown
vs-mcpaudit scan -s "..." -f markdown -o report.md

# SARIF for GitHub Code Scanning
vs-mcpaudit scan -s "..." -o report.sarif
```

### Interactive TUI Dashboard

Live progress with module status, findings stream, and animated score reveal:

```bash
vs-mcpaudit scan -s "..." --active --tui
```

### Auto-Fix Suggestions

Generates code patches for common findings. Each suggestion includes the fix category, effort estimate, and a ready-to-apply patch:

```bash
vs-mcpaudit scan -s "..." --active --autofix
```

### Executive Summary

A business-language risk assessment for non-technical stakeholders (CISOs, VPs, compliance teams):

```bash
vs-mcpaudit scan -s "..." --active --executive-summary
```

### Score Badge

Generate an SVG badge for your README or dashboard:

```bash
# From a previous report
vs-mcpaudit badge -i report.json -o badge.svg

# Manual score
vs-mcpaudit badge --score 85 -o badge.svg
```

---

## CI/CD Integration

### GitHub Action (Marketplace)

Use the official GitHub Action for one-line CI integration:

```yaml
name: MCP Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: MCP Security Scan
        id: scan
        uses: volodymyrshk/vs-mcpaudit@v1
        with:
          server: "node dist/server.js"
          profile: standard
          fail-below: 70
          sarif: results.sarif
          compliance: all

      - name: Check Score
        run: |
          echo "Security Score: ${{ steps.scan.outputs.score }}/100 (${{ steps.scan.outputs.grade }})"
          echo "Findings: ${{ steps.scan.outputs.findings }} (${{ steps.scan.outputs.critical }} critical)"
```

#### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `server` | MCP server command to scan | *required* |
| `profile` | Scan profile (`quick`, `standard`, `enterprise`) | `standard` |
| `fail-below` | Fail if score is below this threshold (0-100) | `0` (disabled) |
| `format` | Output format | `terminal` |
| `sarif` | Path for SARIF output (enables GitHub Code Scanning) | none |
| `output` | Path to save JSON report | `report.json` |
| `compliance` | Compliance frameworks (`nist`, `soc2`, `asvs`, `all`) | none |
| `rules` | Path to custom rules YAML file | none |
| `min-severity` | Minimum severity to report | all |
| `modules` | Space-separated module IDs | all |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `grade` | Letter grade (A+, A, B, C, D, F) |
| `findings` | Total number of findings |
| `critical` | Number of CRITICAL findings |
| `high` | Number of HIGH findings |
| `report-path` | Path to the saved report |

### Manual CI Setup

```yaml
- name: MCP Security Scan
  run: |
    npx vs-mcpaudit scan \
      -s "node dist/server.js" \
      --active --ci \
      --fail-below 70 \
      -o results.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### CI Score Gate (`--fail-below`)

Enforce a minimum security score in CI pipelines:

```bash
# Fail the build if score drops below 70
vs-mcpaudit scan -s "..." --active --ci --fail-below 70

# Exit codes:
#   0 — all clear
#   1 — warnings only
#   2 — failed checks
#   3 — CRITICAL findings
#   5 — score below --fail-below threshold
```

### Git Pre-Commit Hook

```bash
# Install hook
vs-mcpaudit hook install

# Uninstall
vs-mcpaudit hook uninstall
```

### Report Diffing

Compare two reports to track security posture over time:

```bash
vs-mcpaudit diff baseline.json current.json
```

---

## Fleet Scanning (Enterprise)

Scan multiple MCP servers in one command using a registry file:

```bash
vs-mcpaudit scan-all -r registry.json --accept
```

**registry.json:**
```json
{
  "servers": [
    { "name": "filesystem", "command": "npx -y @modelcontextprotocol/server-filesystem /tmp" },
    { "name": "database", "command": "node db-server.js", "active": true },
    { "name": "custom", "command": "./my-server", "profile": "enterprise" }
  ],
  "defaults": {
    "profile": "standard",
    "compliance": ["all"],
    "timeout": 30000
  }
}
```

Each server can override: `transport`, `active`, `profile`, `compliance`, `modules`, `timeout`.

Save individual reports to a directory:

```bash
vs-mcpaudit scan-all -r registry.json -o ./reports --accept
```

### Docker

```bash
# Build the image
docker build -t vs-mcpaudit .

# Single server scan
docker run vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile enterprise

# Fleet scan with registry
docker run \
  -v ./registry.json:/scan/registry.json:ro \
  -v ./reports:/scan/reports \
  vs-mcpaudit scan-all -r /scan/registry.json -o /scan/reports
```

For **Kubernetes**, run as a `CronJob` with the registry mounted as a ConfigMap:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: mcp-security-audit
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: mcpaudit
              image: vs-mcpaudit:latest
              args: ["scan-all", "-r", "/config/registry.json", "-o", "/reports", "--accept"]
              volumeMounts:
                - name: registry
                  mountPath: /config
                - name: reports
                  mountPath: /reports
          volumes:
            - name: registry
              configMap:
                name: mcp-registry
            - name: reports
              persistentVolumeClaim:
                claimName: audit-reports
          restartPolicy: OnFailure
```

---

## Compliance Mapping

Map findings to industry-standard frameworks with `--compliance`:

```bash
vs-mcpaudit scan -s "..." --active --compliance all
```

| Framework | Flag | Controls |
|-----------|------|----------|
| NIST SP 800-171 | `nist` | Access control, audit, identification, system integrity |
| SOC 2 TSC | `soc2` | CC6.1, CC6.6, CC7.1, CC7.2 trust services criteria |
| OWASP ASVS | `asvs` | V5 (validation), V7 (crypto), V13 (API) verification |

---

## Configuration

Create a config file to avoid repeating flags:

```bash
vs-mcpaudit init
```

This creates `.mcpauditrc.json`:

```json
{
  "profile": "standard",
  "format": "terminal",
  "active": false,
  "compliance": [],
  "modules": [],
  "ignore": [],
  "timeout": 30000,
  "probeTimeout": 5000,
  "probeDelay": 100
}
```

CLI flags always override config file values.

---

## All Commands

| Command | Description |
|---------|-------------|
| *(no command)* | Interactive wizard — guided setup for first-time users |
| `scan` | Scan an MCP server for security vulnerabilities |
| `scan-all` | Scan multiple servers from a registry file (fleet scanning) |
| `audit-local` | Discover and scan all MCP servers from local IDE configs |
| `badge` | Generate an SVG score badge |
| `diff` | Compare two scan reports (new/fixed findings) |
| `hook` | Manage git pre-commit hook (install/uninstall) |
| `list-modules` | List all available audit modules and scan profiles |
| `init` | Create a `.mcpauditrc.json` config file |

## Scan Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s, --server <cmd>` | MCP server command to scan | *required* |
| `-p, --profile` | Scan profile (`quick`, `standard`, `enterprise`) | none |
| `-t, --transport` | Transport type (`stdio` or `streamable-http`) | `stdio` |
| `-f, --format` | Output format (`terminal`, `json`, `html`, `markdown`) | `terminal` |
| `--active` | Enable active scanning modules | `false` |
| `-m, --modules` | Run specific modules only | all |
| `--rules <file>` | Custom policy rules file (YAML or JSON) | none |
| `--fail-below <score>` | Fail if score is below threshold (0-100) | disabled |
| `--ci` | CI mode (no color, JSON, non-zero exit) | `false` |
| `--tui` | Interactive TUI dashboard | auto in TTY |
| `--autofix` | Show auto-fix suggestions with code patches | auto in TTY |
| `--executive-summary` | Include executive summary | auto in TTY |
| `--compliance` | Enable compliance mapping (`nist`, `soc2`, `asvs`, `all`) | none |
| `--min-severity` | Filter findings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) | all |
| `--payloads <file>` | Custom fuzzing payloads JSON file | none |
| `--config <file>` | Config file path | `.mcpauditrc.json` |
| `-o, --output <file>` | Save report to file (`.sarif` for SARIF) | stdout |
| `-v, --verbose` | Verbose output | `false` |
| `--timeout <ms>` | Connection timeout | `30000` |
| `--probe-timeout <ms>` | Timeout per active probe | `5000` |
| `--probe-delay <ms>` | Delay between probes | `100` |

---

## Architecture

vs-mcpaudit is designed with adapter-based architecture to support multiple agent tool ecosystems:

```
┌─────────────────────────────────────────────────────────┐
│                     vs-mcpaudit                         │
├──────────┬───────────────┬──────────────┬───────────────┤
│  Module  │   Rules DSL   │   Scoring    │   Reporting   │
│  Runner  │   Engine      │   Engine     │   (5 formats) │
├──────────┴───────────────┴──────────────┴───────────────┤
│                 Adapter Layer                            │
├──────────┬───────────────┬──────────────┬───────────────┤
│   MCP    │  OpenAI Tool  │  LangChain   │   REST API    │
│  Client  │  Schema (TBD) │  Tools (TBD) │  Audit (TBD)  │
└──────────┴───────────────┴──────────────┴───────────────┘
```

The MCP adapter is fully implemented. Additional adapters for OpenAI function calling, LangChain tool registries, and generic REST tool endpoints are on the roadmap.

---

## Development

```bash
# Install dependencies
bun install

# Run from source
bun run packages/cli/src/index.ts scan -s "..." --accept

# Run tests (283 tests, 687 assertions)
cd packages/cli && bun test

# Type check
bun run typecheck

# Build
bun run build
```

---

## License

Apache-2.0
