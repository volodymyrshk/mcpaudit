import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * Supply Chain Analysis Module (Passive).
 *
 * Analyzes the MCP server's supply chain risks:
 * 1. Package name typosquatting indicators
 * 2. Suspicious server metadata (version, name patterns)
 * 3. Excessive capability requests relative to tool count
 * 4. Known malicious package name patterns
 * 5. Server version freshness and consistency
 *
 * PASSIVE MODULE: analyzes metadata only, no tool calls.
 *
 * CWE-1357: Reliance on Insufficiently Trustworthy Component
 */
export class SupplyChainAnalysisModule implements AuditModule {
  id = "supply-chain-analysis";
  name = "Supply Chain Analysis";
  description =
    "Analyzes server metadata and naming for supply-chain risk indicators";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { capabilities } = context;

    // Check 1: Package name typosquatting
    checks.push(this.checkTyposquatting(capabilities.serverInfo.name));

    // Check 2: Suspicious server metadata
    checks.push(this.checkSuspiciousMetadata(
      capabilities.serverInfo.name,
      capabilities.serverInfo.version
    ));

    // Check 3: Capability sprawl — excessive capabilities vs tool count
    checks.push(this.checkCapabilitySprawl(capabilities));

    // Check 4: Version anomalies
    checks.push(this.checkVersionAnomalies(capabilities.serverInfo.version));

    // Check 5: Tool count anomalies
    checks.push(this.checkToolCountAnomalies(capabilities));

    return checks;
  }

  /**
   * Check for typosquatting indicators in the server/package name.
   * Looks for common typosquatting patterns used in npm attacks.
   */
  private checkTyposquatting(serverName: string): CheckResult {
    const name = serverName.toLowerCase();
    const indicators: string[] = [];

    // Known popular MCP package prefixes
    const popularPrefixes = [
      "modelcontextprotocol",
      "mcp-server",
      "mcp-tool",
      "anthropic",
      "claude",
    ];

    // Check for near-miss typos of popular packages
    for (const prefix of popularPrefixes) {
      if (name === prefix) continue; // Exact match is fine
      const distance = this.levenshteinDistance(name, prefix);
      if (distance > 0 && distance <= 2) {
        indicators.push(`Name "${serverName}" is ${distance} edit(s) from "${prefix}"`);
      }

      // Check for homoglyph substitution (0 for o, 1 for l, etc.)
      const homoglyphVersion = prefix
        .replace(/o/g, "0")
        .replace(/l/g, "1")
        .replace(/i/g, "1");
      if (name === homoglyphVersion && name !== prefix) {
        indicators.push(`Name "${serverName}" uses homoglyph substitution of "${prefix}"`);
      }
    }

    // Check for suspicious naming patterns
    if (name.includes("--")) {
      indicators.push("Double-dash in package name (npm scoping confusion)");
    }
    if (/^@[^/]+\//.test(name) === false && name.includes("official")) {
      indicators.push("Claims 'official' but not scoped to an org");
    }
    if (/\d{4,}/.test(name)) {
      indicators.push("Contains suspiciously long numeric suffix");
    }
    if (name.endsWith("-dev") || name.endsWith("-test") || name.endsWith("-debug")) {
      indicators.push(`Suspicious suffix: "${name.split("-").pop()}"`);
    }

    if (indicators.length === 0) {
      return {
        id: "SC-001",
        name: "Package name typosquatting check",
        status: CheckStatus.PASS,
        message: `Server name "${serverName}" shows no typosquatting indicators`,
      };
    }

    return {
      id: "SC-001",
      name: "Package name typosquatting check",
      status: CheckStatus.WARN,
      message: `${indicators.length} typosquatting indicator(s) found`,
      finding: {
        id: "SC-001",
        module: this.id,
        severity: Severity.HIGH,
        title: "Possible typosquatting in server package name",
        description:
          `Server "${serverName}" exhibits naming patterns commonly associated with ` +
          "typosquatting attacks in package registries. This could indicate a malicious " +
          "package impersonating a legitimate MCP server.",
        evidence: { serverName, indicators },
        remediation:
          "Verify the server package name against the official registry. " +
          "Check the package publisher and download count. " +
          "Compare with the canonical package name for the intended server. " +
          "Use lockfiles and hash verification to pin dependencies.",
        cweId: "CWE-1357",
      },
    };
  }

  /**
   * Check server metadata for suspicious patterns.
   */
  private checkSuspiciousMetadata(serverName: string, version: string): CheckResult {
    const issues: string[] = [];

    // Empty or placeholder name
    if (!serverName || serverName === "unknown" || serverName === "test") {
      issues.push("Server name is empty or placeholder-like");
    }

    // Empty or placeholder version
    if (!version || version === "0.0.0" || version === "unknown") {
      issues.push("Server version is empty or placeholder-like");
    }

    // Suspiciously generic description in name
    if (/^(server|tool|api|service)$/i.test(serverName)) {
      issues.push("Server name is suspiciously generic");
    }

    // Check for dev/staging indicators in production
    const devIndicators = ["localhost", "staging", "beta", "alpha", "canary", "nightly"];
    for (const indicator of devIndicators) {
      if (serverName.toLowerCase().includes(indicator)) {
        issues.push(`Server name contains dev/staging indicator: "${indicator}"`);
      }
    }

    if (issues.length === 0) {
      return {
        id: "SC-002",
        name: "Server metadata analysis",
        status: CheckStatus.PASS,
        message: "Server metadata appears legitimate",
      };
    }

    return {
      id: "SC-002",
      name: "Server metadata analysis",
      status: CheckStatus.WARN,
      message: `${issues.length} metadata issue(s) found`,
      finding: {
        id: "SC-002",
        module: this.id,
        severity: Severity.LOW,
        title: "Suspicious server metadata",
        description:
          `Server "${serverName}" v${version} has metadata patterns that may indicate ` +
          "an incomplete, staging, or potentially malicious server deployment.",
        evidence: { serverName, version, issues },
        remediation:
          "Ensure the server has proper identification metadata. " +
          "Use semantic versioning and meaningful server names. " +
          "Remove dev/staging indicators from production deployments.",
        cweId: "CWE-1357",
      },
    };
  }

  /**
   * Check for capability sprawl — servers requesting more capabilities
   * than their tool count justifies.
   */
  private checkCapabilitySprawl(capabilities: ModuleContext["capabilities"]): CheckResult {
    const toolCount = capabilities.tools.length;
    const resourceCount = capabilities.resources.length;
    const promptCount = capabilities.prompts.length;
    const totalSurface = toolCount + resourceCount + promptCount;
    const issues: string[] = [];

    // Large number of tools with no resources/prompts (potential kitchen-sink)
    if (toolCount > 20 && resourceCount === 0 && promptCount === 0) {
      issues.push(
        `${toolCount} tools with zero resources/prompts — potential over-permissioned server`
      );
    }

    // Tools with destructive annotations relative to total
    const destructiveTools = capabilities.tools.filter(
      (t) => t.annotations?.destructiveHint === true
    );
    if (destructiveTools.length > toolCount * 0.5 && toolCount > 3) {
      issues.push(
        `${destructiveTools.length}/${toolCount} tools marked destructive — high-risk server`
      );
    }

    // No annotations at all (lack of safety metadata)
    const annotatedTools = capabilities.tools.filter(
      (t) => t.annotations && Object.keys(t.annotations).length > 0
    );
    if (annotatedTools.length === 0 && toolCount > 0) {
      issues.push(
        `No tool annotations declared — server provides no safety metadata`
      );
    }

    // Attack surface assessment
    if (totalSurface > 50) {
      issues.push(
        `Large attack surface: ${totalSurface} total capabilities (${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts)`
      );
    }

    if (issues.length === 0) {
      return {
        id: "SC-003",
        name: "Capability sprawl analysis",
        status: CheckStatus.PASS,
        message: `Attack surface: ${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts`,
      };
    }

    return {
      id: "SC-003",
      name: "Capability sprawl analysis",
      status: CheckStatus.WARN,
      message: `${issues.length} capability concern(s) found`,
      finding: {
        id: "SC-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Excessive or poorly annotated capability surface",
        description:
          "The server's capability surface raises concerns about over-permissioning " +
          "or inadequate safety metadata. " +
          issues.join(". ") + ".",
        evidence: {
          toolCount,
          resourceCount,
          promptCount,
          destructiveToolCount: destructiveTools.length,
          annotatedToolCount: annotatedTools.length,
          issues,
        },
        remediation:
          "Apply the principle of least privilege — only expose necessary tools. " +
          "Add safety annotations (readOnlyHint, destructiveHint) to all tools. " +
          "Split large tool sets into focused server packages. " +
          "Document the security posture of each tool.",
        cweId: "CWE-250",
      },
    };
  }

  /**
   * Check version string for anomalies.
   */
  private checkVersionAnomalies(version: string): CheckResult {
    const issues: string[] = [];

    // Not semver
    if (!/^\d+\.\d+\.\d+/.test(version)) {
      issues.push(`Version "${version}" is not semantic versioning`);
    }

    // Very old major version 0.0.x
    if (/^0\.0\.\d+$/.test(version)) {
      issues.push("Pre-release version (0.0.x) — may be unstable or experimental");
    }

    // Suspiciously high version
    const parts = version.split(".");
    if (parts.length >= 1 && parseInt(parts[0], 10) > 100) {
      issues.push(`Suspiciously high major version: ${parts[0]}`);
    }

    if (issues.length === 0) {
      return {
        id: "SC-004",
        name: "Version integrity check",
        status: CheckStatus.PASS,
        message: `Version "${version}" follows expected conventions`,
      };
    }

    return {
      id: "SC-004",
      name: "Version integrity check",
      status: CheckStatus.WARN,
      message: issues[0],
    };
  }

  /**
   * Check for tool count anomalies (zero tools, suspiciously high counts).
   */
  private checkToolCountAnomalies(
    capabilities: ModuleContext["capabilities"]
  ): CheckResult {
    const toolCount = capabilities.tools.length;

    if (toolCount === 0) {
      return {
        id: "SC-005",
        name: "Tool count analysis",
        status: CheckStatus.WARN,
        message: "Server exposes zero tools — may be misconfigured",
        finding: {
          id: "SC-005",
          module: this.id,
          severity: Severity.LOW,
          title: "Server exposes no tools",
          description:
            "The MCP server advertises zero tools. This may indicate a misconfigured " +
            "server, a server in initialization state, or a server that only provides " +
            "resources/prompts without tool functionality.",
          evidence: { toolCount: 0 },
          remediation:
            "Verify the server is properly configured and initialized. " +
            "Ensure the server's tool registration is working correctly.",
          cweId: "CWE-1357",
        },
      };
    }

    return {
      id: "SC-005",
      name: "Tool count analysis",
      status: CheckStatus.PASS,
      message: `Server exposes ${toolCount} tool(s)`,
    };
  }

  /**
   * Calculate Levenshtein distance between two strings.
   */
  private levenshteinDistance(a: string, b: string): number {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = a[j - 1] === b[i - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[b.length][a.length];
  }
}
