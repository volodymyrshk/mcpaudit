# vs-mcpaudit

![](https://img.shields.io/badge/Node.js-20%2B-brightgreen?style=flat-square) ![](https://img.shields.io/badge/Bun-1.1%2B-orange?style=flat-square) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

vs-mcpaudit is a specialized security scanner for Model Context Protocol (MCP) servers. It helps developers and security teams identify vulnerabilities, schema weaknesses, and data exfiltration paths in MCP servers before they are exposed to AI agents.

**Learn more in the [official documentation](https://github.com/volodymyrshk/mcpaudit#modules)**.

## Get started

vs-mcpaudit is distributed as a standalone CLI tool. You can run it directly via `npx` or install it globally.

1.  **Run with npx (Recommended):**
    ```bash
    npx vs-mcpaudit scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp"
    ```

2.  **Install globally:**
    ```bash
    # Via NPM
    npm install -g vs-mcpaudit

    # Via Bun
    bun install -g vs-mcpaudit
    ```

3.  **From source:**
    ```bash
    git clone https://github.com/volodymyrshk/mcpaudit.git
    cd mcpaudit
    bun install
    bun run build
    ./packages/cli/dist/index.js --help
    ```

## Core Modules

vs-mcpaudit features six specialized audit modules designed to uncover common MCP security pitfalls:

### Tool Permissions (`tool-permissions`)
Analyzes tool schemas for over-permissioning, dangerous naming patterns, and annotation trust issues.
- **Detections:** Missing descriptions, unconstrained parameters, contradictory annotations, and risky tool names (command exec, destructive ops).

### SSRF Detection (`ssrf-detection`)
**Active Scanning Module.** Probes tools with URL parameters using controlled SSRF payloads.
- **Detections:** Successful loopback access, cloud metadata endpoint exposure (AWS/GCP/Azure), and protocol smuggling.

### Active Parameter Fuzzing (`active-fuzzer`)
**Active Scanning Module.** Fuzzes tool parameters with adversarial payloads to test input validation and sanitation.
- **Detections:** Command injection (CWE-78), Path traversal (CWE-22), SQL injection (CWE-89), and XSS reflection (CWE-79).

### Transport Security (`transport-security`)
Evaluates server capability declarations and transport-layer configurations.
- **Detections:** Sampling/Roots capability abuse, dynamic tool registration poisoning, and sensitive resource exposure.

### Schema Manipulation (`schema-manipulation`)
Detects structural weaknesses in tool schemas that could enable injection or validation bypass.

### Context Extraction (`context-extraction`)
Identifies tools and resources that could leak sensitive environment context or be used for stealthy data exfiltration.

## CI/CD Integration

vs-mcpaudit is designed to run in automated pipelines. Use the `--ci` flag for non-interactive output and machine-readable results.

### GitHub Actions Example

```yaml
- name: MCP Security Scan
  run: npx vs-mcpaudit scan -s "your-mcp-server" --ci -o results.sarif

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Output Formats

| `terminal` | Rich, color-coded interactive report | Local development and manual auditing |
| `json` | Structured machine-readable data | Scripting and custom integrations |
| `sarif` | Static Analysis Results Interchange Format | GitHub Code Scanning & IDE integrations |

## Compliance Mapping

vs-mcpaudit can map security findings to industry-standard compliance frameworks using the `--compliance` flag.

- **OWASP Top 10 2021**: Maps findings to standard web security categories.
- **NIST 800-53 Rev 5**: Maps findings to federal security controls.
- **MITRE ATLAS**: Maps findings to adversarial AI techniques and tactics.

## Reporting Issues

We welcome feedback and bug reports. Please file an issue on the [GitHub repository](https://github.com/volodymyrshk/mcpaudit/issues).

## License

Apache-2.0
