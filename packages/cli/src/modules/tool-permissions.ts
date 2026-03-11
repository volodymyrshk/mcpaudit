import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Dangerous tool name patterns that indicate potentially high-risk operations.
 */
const DANGEROUS_NAME_PATTERNS = [
  { pattern: /exec|execute|run|shell|command|subprocess|spawn/i, category: "command-execution" },
  { pattern: /delete|remove|destroy|drop|truncate|purge|wipe/i, category: "destructive" },
  { pattern: /write|create|mkdir|put|upload|save|modify|update|patch/i, category: "write-operations" },
  { pattern: /fetch|request|http|curl|wget|download|get_url/i, category: "network-access" },
  { pattern: /sql|query|database|db_/i, category: "database-access" },
  { pattern: /admin|root|sudo|privilege|escalat/i, category: "elevated-access" },
];

/**
 * Dangerous parameter name patterns in tool input schemas.
 */
const DANGEROUS_PARAM_PATTERNS = [
  { pattern: /^(command|cmd|exec|shell|script|code)$/i, risk: "command-injection" },
  { pattern: /^(path|file|filepath|filename|dir|directory)$/i, risk: "path-traversal" },
  { pattern: /^(url|uri|endpoint|href|link|src|webhook|callback)$/i, risk: "ssrf" },
  { pattern: /^(query|sql|statement|expression)$/i, risk: "injection" },
  { pattern: /^(html|template|body|content|markup)$/i, risk: "xss" },
];

/**
 * Tool Permissions Analysis Module.
 *
 * Analyzes tool schemas for over-permissioning, dangerous patterns,
 * missing constraints, and annotation trust issues.
 *
 * This module implements the MCP specification's own warning:
 * "Tool annotations MUST be considered untrusted unless they come from trusted servers."
 */
export class ToolPermissionsModule implements AuditModule {
  id = "tool-permissions";
  name = "Tool Permissions Analysis";
  description =
    "Analyzes tool schemas for over-permissioning, dangerous patterns, and annotation trust issues";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    // ── Check 1: Tool count assessment ─────────────────────────────────
    checks.push(this.checkToolCount(tools));

    // ── Check 2: Tools with no descriptions ────────────────────────────
    checks.push(this.checkMissingDescriptions(tools));

    // ── Check 3: Dangerous tool name patterns ──────────────────────────
    checks.push(...this.checkDangerousNames(tools));

    // ── Check 4: Schema constraint analysis (per tool) ─────────────────
    for (const tool of tools) {
      checks.push(...this.analyzeToolSchema(tool));
    }

    // ── Check 5: Annotation trust analysis ─────────────────────────────
    checks.push(...this.checkAnnotationTrust(tools));

    // ── Check 6: Tools with additionalProperties ───────────────────────
    checks.push(this.checkAdditionalProperties(tools));

    return checks;
  }

  // ─── Individual Checks ─────────────────────────────────────────────────────

  private checkToolCount(tools: ToolInfo[]): CheckResult {
    const count = tools.length;
    if (count === 0) {
      return {
        id: "TP-001",
        name: "Tool exposure count",
        status: CheckStatus.PASS,
        message: "No tools exposed",
      };
    }

    if (count > 20) {
      return {
        id: "TP-001",
        name: "Tool exposure count",
        status: CheckStatus.WARN,
        message: `${count} tools exposed — large attack surface`,
        finding: {
          id: "TP-001",
          module: this.id,
          severity: Severity.LOW,
          title: "Large number of tools exposed",
          description: `Server exposes ${count} tools. A larger tool surface increases the risk of over-permissioning and makes manual review more difficult.`,
          evidence: { toolCount: count },
          remediation:
            "Consider reducing the number of exposed tools to only those required for the intended use case. Use tool filtering or separate server profiles.",
          cweId: "CWE-250",
        },
      };
    }

    return {
      id: "TP-001",
      name: "Tool exposure count",
      status: CheckStatus.PASS,
      message: `${count} tools exposed`,
    };
  }

  private checkMissingDescriptions(tools: ToolInfo[]): CheckResult {
    const undescribed = tools.filter(
      (t) => !t.description || t.description.trim().length === 0
    );

    if (undescribed.length === 0) {
      return {
        id: "TP-002",
        name: "Tool descriptions present",
        status: CheckStatus.PASS,
        message: "All tools have descriptions",
      };
    }

    return {
      id: "TP-002",
      name: "Tool descriptions present",
      status: CheckStatus.WARN,
      message: `${undescribed.length} tool(s) missing descriptions`,
      finding: {
        id: "TP-002",
        module: this.id,
        severity: Severity.LOW,
        title: "Tools missing descriptions",
        description: `${undescribed.length} tool(s) have no description. Missing descriptions make it difficult for AI agents to understand tool behavior and for security reviewers to assess risk.`,
        evidence: {
          tools: undescribed.map((t) => t.name),
        },
        remediation:
          "Add clear, accurate descriptions to all tools explaining their purpose, side effects, and any security implications.",
        cweId: "CWE-1059",
      },
    };
  }

  private checkDangerousNames(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const dangerousTools: Array<{ tool: string; category: string; pattern: string }> = [];

    for (const tool of tools) {
      for (const { pattern, category } of DANGEROUS_NAME_PATTERNS) {
        if (pattern.test(tool.name)) {
          dangerousTools.push({
            tool: tool.name,
            category,
            pattern: pattern.source,
          });
          break; // One match per tool is enough
        }
      }
    }

    if (dangerousTools.length === 0) {
      checks.push({
        id: "TP-003",
        name: "Dangerous tool name patterns",
        status: CheckStatus.PASS,
        message: "No dangerous naming patterns detected",
      });
    } else {
      // Group by category
      const categories = new Map<string, string[]>();
      for (const dt of dangerousTools) {
        const list = categories.get(dt.category) ?? [];
        list.push(dt.tool);
        categories.set(dt.category, list);
      }

      const cweMap: Record<string, string> = {
        "command-execution": "CWE-78",
        "destructive": "CWE-862",
        "write-operations": "CWE-862",
        "network-access": "CWE-918",
        "database-access": "CWE-89",
        "elevated-access": "CWE-269",
      };

      for (const [category, toolNames] of categories) {
        const severity =
          category === "command-execution" || category === "elevated-access"
            ? Severity.HIGH
            : category === "destructive"
              ? Severity.MEDIUM
              : Severity.LOW;

        checks.push({
          id: `TP-003-${category}`,
          name: `Dangerous tools: ${category}`,
          status: severity === Severity.HIGH ? CheckStatus.FAIL : CheckStatus.WARN,
          message: `${toolNames.length} tool(s) with ${category} patterns: ${toolNames.join(", ")}`,
          finding: {
            id: `TP-003-${category}`,
            module: this.id,
            severity,
            title: `Tools with ${category} naming patterns`,
            description: `${toolNames.length} tool(s) have names suggesting ${category} capabilities. These tools may pose elevated security risks if not properly constrained.`,
            evidence: { category, tools: toolNames },
            remediation: `Review these tools for appropriate input validation, access controls, and documentation of security implications. Consider restricting tool availability via MCP server configuration.`,
            cweId: cweMap[category] ?? "CWE-250",
          },
        });
      }
    }

    return checks;
  }

  private analyzeToolSchema(tool: ToolInfo): CheckResult[] {
    const checks: CheckResult[] = [];

    if (!tool.inputSchema || typeof tool.inputSchema !== "object") {
      checks.push({
        id: `TP-004-${tool.name}`,
        name: `Schema validation: ${tool.name}`,
        status: CheckStatus.WARN,
        message: "Tool has no input schema defined",
        finding: {
          id: `TP-004-${tool.name}`,
          module: this.id,
          severity: Severity.MEDIUM,
          title: `Missing input schema for tool "${tool.name}"`,
          description:
            "Tool has no input schema, meaning any input will be accepted without validation. This significantly increases the risk of injection attacks.",
          evidence: { toolName: tool.name },
          remediation:
            "Define a strict JSON Schema for the tool's input parameters with appropriate type constraints, enums, and patterns.",
          toolName: tool.name,
          cweId: "CWE-20",
        },
      });
      return checks; // Skip further schema validation
    }

    // Analyze properties if present
    const properties =
      (tool.inputSchema as Record<string, unknown>).properties as
        | Record<string, Record<string, unknown>>
        | undefined;

    if (!properties) return checks;

    // Check each property for dangerous patterns
    const dangerousParams: Array<{
      param: string;
      risk: string;
      issues: string[];
    }> = [];

    for (const [paramName, paramSchema] of Object.entries(properties)) {
      const issues: string[] = [];

      // Check for dangerous parameter names
      for (const { pattern, risk } of DANGEROUS_PARAM_PATTERNS) {
        if (pattern.test(paramName)) {
          // Check if the parameter has proper constraints
          if (
            paramSchema.type === "string" &&
            !paramSchema.enum &&
            !paramSchema.pattern &&
            !paramSchema.maxLength
          ) {
            issues.push(
              `Unconstrained string parameter "${paramName}" suggests ${risk} risk`
            );
          }

          if (issues.length > 0) {
            dangerousParams.push({ param: paramName, risk, issues });
          }
        }
      }
    }

    if (dangerousParams.length > 0) {
      checks.push({
        id: `TP-005-${tool.name}`,
        name: `Schema constraints: ${tool.name}`,
        status: CheckStatus.WARN,
        message: `${dangerousParams.length} parameter(s) with insufficient constraints`,
        finding: {
          id: `TP-005-${tool.name}`,
          module: this.id,
          severity: Severity.MEDIUM,
          title: `Unconstrained parameters in tool "${tool.name}"`,
          description: `Tool has ${dangerousParams.length} parameter(s) that suggest security-sensitive operations but lack proper input validation constraints (enum, pattern, maxLength).`,
          evidence: {
            toolName: tool.name,
            parameters: dangerousParams,
          },
          remediation:
            "Add appropriate constraints to input schema: use 'enum' for fixed values, 'pattern' for format validation, 'maxLength' to prevent oversized inputs, and avoid accepting arbitrary strings for security-sensitive parameters.",
          toolName: tool.name,
          cweId: "CWE-20",
        },
      });
    } else if (Object.keys(properties).length > 0) {
      checks.push({
        id: `TP-005-${tool.name}`,
        name: `Schema constraints: ${tool.name}`,
        status: CheckStatus.PASS,
        message: "Parameters appear properly constrained",
      });
    }

    return checks;
  }

  private checkAnnotationTrust(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const missingAnnotations = tools.filter((t) => !t.annotations);
    const suspiciousAnnotations: Array<{
      tool: string;
      issue: string;
    }> = [];

    // Check for missing annotations
    if (missingAnnotations.length > 0 && tools.length > 0) {
      checks.push({
        id: "TP-006",
        name: "Tool annotations present",
        status: CheckStatus.WARN,
        message: `${missingAnnotations.length}/${tools.length} tools have no annotations`,
        finding: {
          id: "TP-006",
          module: this.id,
          severity: Severity.LOW,
          title: "Tools missing annotations",
          description: `${missingAnnotations.length} tool(s) have no annotations (readOnlyHint, destructiveHint, etc.). Per the MCP specification, annotations help AI agents make informed decisions about tool usage. Missing annotations provide no guidance to agents.`,
          evidence: {
            tools: missingAnnotations.map((t) => t.name),
          },
          remediation:
            "Add annotations to all tools: readOnlyHint for read-only tools, destructiveHint for tools that modify state, and openWorldHint for tools that access external systems.",
          cweId: "CWE-1059",
        },
      });
    } else if (tools.length > 0) {
      checks.push({
        id: "TP-006",
        name: "Tool annotations present",
        status: CheckStatus.PASS,
        message: "All tools have annotations",
      });
    }

    // Check for contradictory annotations (e.g., name says "delete" but readOnlyHint is true)
    for (const tool of tools) {
      if (!tool.annotations) continue;

      // Check: destructive-sounding tool marked as readOnly
      const isDestructiveName =
        /delete|remove|destroy|drop|truncate|purge|wipe|write|create|update|modify/i.test(
          tool.name
        );
      if (isDestructiveName && tool.annotations.readOnlyHint === true) {
        suspiciousAnnotations.push({
          tool: tool.name,
          issue: `Tool name suggests state modification but readOnlyHint is true`,
        });
      }

      // Check: openWorldHint true with no URL restrictions visible
      if (tool.annotations.openWorldHint === true) {
        const hasUrlParams = Object.keys(
          ((tool.inputSchema as Record<string, unknown>)?.properties as Record<string, unknown>) ?? {}
        ).some((name) => /url|uri|endpoint|href/i.test(name));

        if (hasUrlParams) {
          suspiciousAnnotations.push({
            tool: tool.name,
            issue: `Tool has openWorldHint=true and accepts URL parameters — potential SSRF vector`,
          });
        }
      }
    }

    if (suspiciousAnnotations.length > 0) {
      checks.push({
        id: "TP-007",
        name: "Annotation consistency",
        status: CheckStatus.FAIL,
        message: `${suspiciousAnnotations.length} tool(s) have suspicious/contradictory annotations`,
        finding: {
          id: "TP-007",
          module: this.id,
          severity: Severity.HIGH,
          title: "Contradictory or suspicious tool annotations",
          description: `${suspiciousAnnotations.length} tool(s) have annotations that contradict their apparent behavior. Per the MCP spec, annotations "MUST be considered untrusted" — this finding confirms that trust is misplaced.`,
          evidence: { suspiciousAnnotations },
          remediation:
            "Review and correct tool annotations to accurately reflect tool behavior. A tool that modifies state must not have readOnlyHint=true. Tools with openWorldHint=true and URL parameters need URL allowlisting.",
          cweId: "CWE-345",
        },
      });
    } else if (tools.some((t) => !!t.annotations)) {
      checks.push({
        id: "TP-007",
        name: "Annotation consistency",
        status: CheckStatus.PASS,
        message: "Tool annotations appear consistent with tool names",
      });
    }

    return checks;
  }

  private checkAdditionalProperties(tools: ToolInfo[]): CheckResult {
    const toolsWithAdditional: string[] = [];

    for (const tool of tools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      if (schema?.additionalProperties === true) {
        toolsWithAdditional.push(tool.name);
      }
    }

    if (toolsWithAdditional.length === 0) {
      return {
        id: "TP-008",
        name: "Additional properties restricted",
        status: CheckStatus.PASS,
        message:
          tools.length > 0
            ? "No tools allow additional properties"
            : "No tools to check",
      };
    }

    return {
      id: "TP-008",
      name: "Additional properties restricted",
      status: CheckStatus.WARN,
      message: `${toolsWithAdditional.length} tool(s) allow additional properties`,
      finding: {
        id: "TP-008",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Tools accepting additional properties",
        description: `${toolsWithAdditional.length} tool(s) have additionalProperties=true in their input schema, allowing arbitrary key-value pairs to be injected into tool calls.`,
        evidence: { tools: toolsWithAdditional },
        remediation:
          'Set additionalProperties to false in all tool input schemas. Only defined properties with explicit types should be accepted. Example: { "additionalProperties": false }',
        cweId: "CWE-20",
      },
    };
  }
}
