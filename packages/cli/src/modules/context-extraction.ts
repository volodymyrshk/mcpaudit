import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Patterns indicating a tool could be used for data exfiltration.
 * These tools accept user-controlled data and send it to external destinations.
 */
const EXFIL_SINK_PATTERNS = [
  {
    namePattern: /send|post|upload|submit|push|emit|publish|dispatch|forward|relay|transmit/i,
    category: "outbound-data",
    description: "Tool sends data to external destinations",
  },
  {
    namePattern: /email|mail|smtp|notify|alert|message|slack|webhook|discord|telegram/i,
    category: "messaging",
    description: "Tool sends messages to external services",
  },
  {
    namePattern: /log|record|track|audit|report|telemetry|analytics/i,
    category: "logging",
    description: "Tool logs or records data externally",
  },
  {
    namePattern: /write|save|store|put|create/i,
    category: "write-sink",
    description: "Tool writes data to a destination",
  },
];

/**
 * Patterns indicating a tool can access conversation context,
 * system prompts, or other sensitive AI agent state.
 */
const CONTEXT_ACCESS_PATTERNS = [
  {
    namePattern: /context|conversation|history|chat|session|thread|memory/i,
    category: "conversation-access",
    description: "Tool may access conversation history or context",
  },
  {
    namePattern: /prompt|instruction|system|config|setting|preference/i,
    category: "prompt-access",
    description: "Tool may access system prompts or agent instructions",
  },
  {
    namePattern: /env|environment|variable|secret|credential|key|token/i,
    category: "credential-access",
    description: "Tool may access environment variables or credentials",
  },
];

/**
 * Parameter patterns that suggest data exfiltration capability.
 */
const EXFIL_PARAM_PATTERNS = [
  { pattern: /^(to|recipient|destination|target|endpoint|webhook_url|callback_url)$/i, risk: "destination-control" },
  { pattern: /^(body|content|message|payload|data|text|html)$/i, risk: "content-injection" },
  { pattern: /^(subject|title|header|metadata)$/i, risk: "metadata-injection" },
  { pattern: /^(attachment|file|upload)$/i, risk: "file-exfiltration" },
];

/**
 * Context Extraction Module.
 *
 * Identifies tools and tool combinations that could be used to:
 * 1. Extract conversation context or system prompts
 * 2. Exfiltrate data to external services
 * 3. Create covert channels via write + read tool chains
 *
 * This addresses the MCP attack vector where a malicious tool collects
 * sensitive context from the AI agent and sends it to an attacker.
 *
 * Key insight: The danger isn't a single tool — it's the COMBINATION
 * of a tool that can read context + a tool that can send data externally.
 */
export class ContextExtractionModule implements AuditModule {
  id = "context-extraction";
  name = "Context Extraction & Data Exfiltration";
  description =
    "Identifies tools that could exfiltrate conversation context, system prompts, or sensitive data";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    // ── Check 1: Identify outbound data sinks ──────────────────────────
    checks.push(...this.identifyExfilSinks(tools));

    // ── Check 2: Identify context access tools ─────────────────────────
    checks.push(...this.identifyContextAccess(tools));

    // ── Check 3: Cross-tool exfil chains ───────────────────────────────
    checks.push(this.detectExfilChains(tools));

    // ── Check 4: Exfil-capable parameters ──────────────────────────────
    checks.push(...this.checkExfilParameters(tools));

    // ── Check 5: Prompt resource exposure ──────────────────────────────
    checks.push(this.checkPromptExposure(context));

    return checks;
  }

  private identifyExfilSinks(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const sinks: Array<{ tool: string; category: string; description: string }> = [];

    for (const tool of tools) {
      for (const { namePattern, category, description } of EXFIL_SINK_PATTERNS) {
        if (namePattern.test(tool.name)) {
          sinks.push({ tool: tool.name, category, description });
          break;
        }
      }
    }

    if (sinks.length === 0) {
      checks.push({
        id: "CE-001",
        name: "Outbound data sinks",
        status: CheckStatus.PASS,
        message: "No outbound data sink tools detected",
      });
    } else {
      // Higher severity if messaging/webhook sinks exist
      const hasMessaging = sinks.some((s) => s.category === "messaging");
      const hasOutbound = sinks.some((s) => s.category === "outbound-data");

      checks.push({
        id: "CE-001",
        name: "Outbound data sinks",
        status: hasMessaging || hasOutbound ? CheckStatus.WARN : CheckStatus.WARN,
        message: `${sinks.length} tool(s) can send data externally: ${sinks.map((s) => s.tool).join(", ")}`,
        finding: {
          id: "CE-001",
          module: this.id,
          severity: hasMessaging || hasOutbound ? Severity.MEDIUM : Severity.LOW,
          title: "Tools capable of sending data to external destinations",
          description:
            `${sinks.length} tool(s) have names suggesting they can send data externally. ` +
            "These tools could potentially be used by a manipulated AI agent to exfiltrate " +
            "conversation context, system prompts, or user data to an attacker-controlled endpoint.",
          evidence: { sinks },
          remediation:
            "Restrict outbound tools to specific allowlisted destinations. " +
            "Implement content filtering to prevent sensitive data from being included in outbound payloads. " +
            "Require user confirmation for all data-sending operations.",
        },
      });
    }

    return checks;
  }

  private identifyContextAccess(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const accessTools: Array<{ tool: string; category: string; description: string }> = [];

    for (const tool of tools) {
      for (const { namePattern, category, description } of CONTEXT_ACCESS_PATTERNS) {
        if (namePattern.test(tool.name)) {
          accessTools.push({ tool: tool.name, category, description });
          break;
        }
      }
    }

    if (accessTools.length === 0) {
      checks.push({
        id: "CE-002",
        name: "Context access tools",
        status: CheckStatus.PASS,
        message: "No context-access tools detected",
      });
    } else {
      const hasCredentialAccess = accessTools.some(
        (t) => t.category === "credential-access"
      );
      const hasPromptAccess = accessTools.some(
        (t) => t.category === "prompt-access"
      );

      const severity = hasCredentialAccess
        ? Severity.HIGH
        : hasPromptAccess
          ? Severity.MEDIUM
          : Severity.LOW;

      checks.push({
        id: "CE-002",
        name: "Context access tools",
        status:
          severity === Severity.HIGH ? CheckStatus.FAIL : CheckStatus.WARN,
        message: `${accessTools.length} tool(s) may access sensitive context: ${accessTools.map((t) => t.tool).join(", ")}`,
        finding: {
          id: "CE-002",
          module: this.id,
          severity,
          title: "Tools that may access sensitive agent context",
          description:
            `${accessTools.length} tool(s) have names suggesting they can access conversation context, ` +
            "system prompts, environment variables, or credentials. These tools could be exploited " +
            "by a prompt injection attack to extract sensitive information from the AI agent's state.",
          evidence: { accessTools },
          remediation:
            "Minimize the context exposed to MCP tools. Never pass full system prompts or " +
            "conversation history to tool calls. Use scoped tokens instead of raw credentials. " +
            "Implement data loss prevention (DLP) checks on tool inputs and outputs.",
        },
      });
    }

    return checks;
  }

  /**
   * Detect cross-tool exfiltration chains:
   * A server with BOTH context-access tools AND outbound sinks
   * creates a complete exfiltration pipeline.
   */
  private detectExfilChains(tools: ToolInfo[]): CheckResult {
    const contextTools: string[] = [];
    const sinkTools: string[] = [];

    for (const tool of tools) {
      for (const { namePattern } of CONTEXT_ACCESS_PATTERNS) {
        if (namePattern.test(tool.name)) {
          contextTools.push(tool.name);
          break;
        }
      }
      for (const { namePattern } of EXFIL_SINK_PATTERNS) {
        if (namePattern.test(tool.name)) {
          sinkTools.push(tool.name);
          break;
        }
      }
    }

    if (contextTools.length === 0 || sinkTools.length === 0) {
      return {
        id: "CE-003",
        name: "Cross-tool exfiltration chains",
        status: CheckStatus.PASS,
        message: "No complete exfiltration chains detected",
      };
    }

    return {
      id: "CE-003",
      name: "Cross-tool exfiltration chains",
      status: CheckStatus.FAIL,
      message: `Exfiltration chain detected: ${contextTools.length} source(s) + ${sinkTools.length} sink(s)`,
      finding: {
        id: "CE-003",
        module: this.id,
        severity: Severity.HIGH,
        title: "Complete data exfiltration chain available",
        description:
          "The server exposes BOTH tools that access sensitive context AND tools that send data " +
          "externally. A prompt injection attack could chain these tools to: " +
          "(1) read conversation context or credentials, then " +
          "(2) send the extracted data to an attacker-controlled endpoint. " +
          `Sources: ${contextTools.join(", ")}. Sinks: ${sinkTools.join(", ")}.`,
        evidence: { contextTools, sinkTools },
        remediation:
          "Separate context-access tools and outbound tools into different server profiles. " +
          "Never expose both on the same MCP server. If both are required, implement " +
          "server-side data flow controls that prevent tool outputs from being passed as " +
          "inputs to outbound tools without user review.",
      },
    };
  }

  private checkExfilParameters(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const toolsWithExfilParams: Array<{
      tool: string;
      params: Array<{ name: string; risk: string }>;
    }> = [];

    for (const tool of tools) {
      const properties =
        (tool.inputSchema as Record<string, unknown>)?.properties as
          | Record<string, Record<string, unknown>>
          | undefined;

      if (!properties) continue;

      const dangerousParams: Array<{ name: string; risk: string }> = [];
      for (const paramName of Object.keys(properties)) {
        for (const { pattern, risk } of EXFIL_PARAM_PATTERNS) {
          if (pattern.test(paramName)) {
            dangerousParams.push({ name: paramName, risk });
            break;
          }
        }
      }

      if (dangerousParams.length > 0) {
        toolsWithExfilParams.push({ tool: tool.name, params: dangerousParams });
      }
    }

    if (toolsWithExfilParams.length === 0) {
      checks.push({
        id: "CE-004",
        name: "Exfiltration-capable parameters",
        status: CheckStatus.PASS,
        message: "No exfiltration-capable parameter patterns found",
      });
    } else {
      const hasDestination = toolsWithExfilParams.some((t) =>
        t.params.some((p) => p.risk === "destination-control")
      );

      checks.push({
        id: "CE-004",
        name: "Exfiltration-capable parameters",
        status: hasDestination ? CheckStatus.WARN : CheckStatus.PASS,
        message: `${toolsWithExfilParams.length} tool(s) have parameters suggesting data exfiltration capability`,
        finding: hasDestination
          ? {
              id: "CE-004",
              module: this.id,
              severity: Severity.MEDIUM,
              title: "Tools with user-controlled destination parameters",
              description:
                "Tools accept destination parameters (to, recipient, endpoint, webhook_url) that " +
                "allow AI agents to specify where data is sent. A prompt injection could redirect " +
                "sensitive data to attacker-controlled endpoints.",
              evidence: { toolsWithExfilParams },
              remediation:
                "Hardcode or allowlist permitted destinations. Never allow AI agents to " +
                "specify arbitrary URLs, email addresses, or endpoints for outbound data.",
            }
          : undefined,
      });
    }

    return checks;
  }

  /**
   * Check if MCP prompts expose system-level instructions or templates
   * that could reveal internal architecture to an attacker.
   */
  private checkPromptExposure(context: ModuleContext): CheckResult {
    const { prompts } = context.capabilities;

    if (prompts.length === 0) {
      return {
        id: "CE-005",
        name: "Prompt exposure",
        status: CheckStatus.PASS,
        message: "No prompts exposed",
      };
    }

    // Check for prompts with suspicious names
    const sensitivePrompts = prompts.filter((p) =>
      /system|admin|internal|debug|config|secret|credential/i.test(p.name)
    );

    if (sensitivePrompts.length > 0) {
      return {
        id: "CE-005",
        name: "Prompt exposure",
        status: CheckStatus.WARN,
        message: `${sensitivePrompts.length} prompt(s) with sensitive-sounding names`,
        finding: {
          id: "CE-005",
          module: this.id,
          severity: Severity.MEDIUM,
          title: "Potentially sensitive prompts exposed",
          description:
            `${sensitivePrompts.length} MCP prompt(s) have names suggesting they contain ` +
            "system-level instructions, internal configuration, or debug information. " +
            "These prompts are accessible to any connected client and may reveal internal " +
            "architecture or security-sensitive information.",
          evidence: {
            prompts: sensitivePrompts.map((p) => ({
              name: p.name,
              description: p.description,
            })),
          },
          remediation:
            "Review all exposed prompts for sensitive information. Remove debug and admin " +
            "prompts from production server configurations. Use server-side access controls " +
            "to restrict prompt visibility.",
        },
      };
    }

    return {
      id: "CE-005",
      name: "Prompt exposure",
      status: CheckStatus.PASS,
      message: `${prompts.length} prompt(s) exposed, none appear sensitive`,
    };
  }
}
