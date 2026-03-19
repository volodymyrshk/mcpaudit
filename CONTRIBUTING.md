# Contributing to vs-mcpaudit

Thanks for your interest in contributing! vs-mcpaudit is an open-source security audit tool for MCP servers and we welcome contributions of all kinds.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/vs-mcpaudit/vs-mcpaudit.git
cd vs-mcpaudit

# Install dependencies (requires Bun)
bun install

# Run the CLI locally
bun run packages/cli/src/index.ts scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --accept

# Run tests
cd packages/cli && bun test
```

## Project Structure

```
packages/cli/
  src/
    index.ts                  # CLI entry point (Commander.js)
    commands/
      scan.ts                 # Main scan command
      audit-local.ts          # Local config discovery & scan
    core/
      mcp-client.ts           # MCP protocol client
      module-runner.ts        # Module orchestration (parallel passive, sequential active)
      scorer.ts               # Security score calculation
      reporter.ts             # Terminal, JSON, and HTML output
      sarif.ts                # SARIF v2.1.0 output
      acceptance.ts           # First-run legal notice
    modules/                  # Audit modules (see below)
      tool-permissions.ts     # [passive] Schema over-permissioning
      transport-security.ts   # [passive] Transport & capability analysis
      schema-manipulation.ts  # [passive] Prompt injection in descriptions
      context-extraction.ts   # [passive] Data exfiltration chains
      ssrf-detection.ts       # [active]  SSRF probing
      active-fuzzer.ts        # [active]  Parameter fuzzing (6 strategies)
    compliance/
      compliance-enricher.ts  # Maps findings to compliance frameworks
    data/
      compliance-mappings.ts  # CWE -> NIST/SOC2/ASVS control mappings
    types/                    # TypeScript interfaces
    utils/                    # Shared utilities
  tests/                      # Test files (mirror src/ structure)
```

## Adding a New Audit Module

Every audit module implements the `AuditModule` interface:

```typescript
import { CheckStatus, Severity, type AuditModule, type ModuleContext, type CheckResult } from "../types/index.js";

export class MyNewModule implements AuditModule {
  id = "my-new-module";
  name = "My New Security Check";
  description = "Detects something important";
  version = "1.0.0";
  mode = "passive" as const; // or "active"

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools, resources, prompts } = context.capabilities;

    // Your analysis logic here...

    checks.push({
      id: "MY-001",
      name: "My check name",
      status: CheckStatus.PASS, // or WARN, FAIL
      message: "Details about the result",
      // Optional: attach a Finding for WARN/FAIL
      // finding: { id, module, severity, title, description, evidence, remediation }
    });

    return checks;
  }
}
```

### Steps to add a module:

1. **Create the module file** in `src/modules/your-module.ts`
2. **Register it** in `src/commands/scan.ts` in the `getAvailableModules()` function
3. **Add it to `list-modules`** in `src/index.ts`
4. **Write tests** in `tests/modules/your-module.test.ts`
5. **Map CWE IDs** in `src/core/sarif.ts` (`cweToScore()`) if your module uses new CWEs

### Module guidelines:

- **Passive modules** only analyze `context.capabilities` (schemas, metadata). They never call tools.
- **Active modules** use `context.callTool()` to make actual tool calls. They must check `context.callTool` exists and return `SKIP` checks if it doesn't.
- Use `context.onProgress?.()` in active modules to report granular progress.
- Finding IDs follow the pattern: `XX-NNN` (e.g., `TP-001`, `AF-003`).
- Always include `remediation` text in findings.
- Include `cweId` when a CWE mapping is appropriate.

## Adding Compliance Mappings

Compliance mappings live in `src/data/compliance-mappings.ts`. To add a new CWE mapping:

```typescript
// In CWE_COMPLIANCE_MAP:
"CWE-XXX": [
  {
    framework: "NIST SP 800-171",
    controlId: "3.x.x",
    controlTitle: "Control Name",
    requirement: "What this control requires",
  },
  {
    framework: "SOC 2 TSC",
    controlId: "CCx.x",
    controlTitle: "Control Name",
    requirement: "What this control requires",
  },
  {
    framework: "OWASP ASVS",
    controlId: "Vx.x.x",
    controlTitle: "Control Name",
    requirement: "What this control requires",
  },
],
```

Then update the CVSS score mapping in `src/core/sarif.ts` if the CWE is new:

```typescript
// In cweToScore():
case "CWE-XXX": return "7.5"; // CVSS base score as string
```

## Running Tests

```bash
cd packages/cli

# Run all tests
bun test

# Run a specific test file
bun test tests/modules/active-fuzzer.test.ts

# Run tests matching a pattern
bun test --grep "tool-permissions"
```

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Add tests for new modules and significant changes
- Run `bun test` and ensure all tests pass before submitting
- Follow existing code patterns and naming conventions
- Update this guide if you change the project structure
