import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";
import { URL_PARAM_PATTERNS } from "../utils/patterns.js";

/**
 * SSRF canary domains — if the server resolves/fetches these, it proves
 * URL input is not properly validated.
 *
 * These are all controlled or non-routable addresses.
 * NO actual traffic is sent to external services.
 */
const SSRF_PROBES = [
  // Internal network probes (RFC 1918 / loopback)
  { payload: "http://127.0.0.1:80", category: "loopback", description: "IPv4 loopback" },
  { payload: "http://[::1]:80", category: "loopback", description: "IPv6 loopback" },
  { payload: "http://0.0.0.0:80", category: "loopback", description: "All-interfaces bind" },
  { payload: "http://localhost:80", category: "loopback", description: "Localhost hostname" },

  // Cloud metadata endpoints (AWS, GCP, Azure)
  { payload: "http://169.254.169.254/latest/meta-data/", category: "cloud-metadata", description: "AWS IMDS v1" },
  { payload: "http://metadata.google.internal/computeMetadata/v1/", category: "cloud-metadata", description: "GCP metadata" },
  { payload: "http://169.254.169.254/metadata/instance", category: "cloud-metadata", description: "Azure IMDS" },

  // Protocol smuggling
  { payload: "file:///etc/passwd", category: "protocol-smuggling", description: "file:// protocol" },
  { payload: "gopher://127.0.0.1:25/", category: "protocol-smuggling", description: "gopher:// protocol" },

  // DNS rebinding / bypass attempts
  { payload: "http://0x7f000001:80", category: "bypass", description: "Hex-encoded loopback" },
  { payload: "http://017700000001:80", category: "bypass", description: "Octal-encoded loopback" },
  { payload: "http://127.1:80", category: "bypass", description: "Shortened loopback" },

  // Internal network ranges
  { payload: "http://10.0.0.1:80", category: "internal-network", description: "10.x.x.x range" },
  { payload: "http://192.168.1.1:80", category: "internal-network", description: "192.168.x.x range" },
  { payload: "http://172.16.0.1:80", category: "internal-network", description: "172.16.x.x range" },
];

// Removed URL_PARAM_PATTERNS from here, moved to utils/patterns.ts

/**
 * SSRF Detection Module (Active).
 *
 * This module identifies tools that accept URL parameters and probes them
 * with SSRF payloads to test whether the server properly validates URLs.
 *
 * ACTIVE MODULE: This module makes actual tool calls to the server.
 * Only enabled with --active flag.
 *
 * Detection approach:
 * 1. Identify tools with URL-like parameters from their schemas
 * 2. Send SSRF probe payloads (internal IPs, cloud metadata, protocol smuggling)
 * 3. Analyze responses for evidence of successful resolution/fetch
 * 4. Report findings with severity based on what resolved
 */
export class SsrfDetectionModule implements AuditModule {
  id = "ssrf-detection";
  name = "SSRF Detection";
  description =
    "Probes tools with URL parameters for SSRF vulnerabilities using controlled payloads";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    // Step 1: Identify tools with URL parameters
    const urlTools = this.findUrlTools(tools);

    if (urlTools.length === 0) {
      checks.push({
        id: "SSRF-001",
        name: "URL-accepting tools",
        status: CheckStatus.PASS,
        message: "No tools accept URL parameters",
      });
      return checks;
    }

    checks.push({
      id: "SSRF-001",
      name: "URL-accepting tools",
      status: CheckStatus.WARN,
      message: `${urlTools.length} tool(s) accept URL parameters: ${urlTools.map((t) => t.tool.name).join(", ")}`,
      finding: {
        id: "SSRF-001",
        module: this.id,
        severity: Severity.LOW,
        title: "Tools accept URL parameters",
        description: `${urlTools.length} tool(s) accept URL parameters, which are potential SSRF vectors if not properly validated.`,
        evidence: {
          tools: urlTools.map((t) => ({
            name: t.tool.name,
            paramName: t.paramName,
          })),
        },
        remediation:
          "Implement URL allowlisting, block private IP ranges, and validate URL schemes (allow only https://).",
      },
    });

    // Step 2: If we have callTool, probe each URL tool
    if (!context.callTool) {
      checks.push({
        id: "SSRF-002",
        name: "SSRF active probing",
        status: CheckStatus.SKIP,
        message: "Active probing requires --active flag and callTool access",
      });
      return checks;
    }

    // Step 3: Probe each tool with SSRF payloads
    for (const { tool, paramName } of urlTools) {
      const probeResults = await this.probeToolForSsrf(
        tool,
        paramName,
        context.callTool,
        context.verbose
      );
      checks.push(...probeResults);
    }

    return checks;
  }

  /**
   * Find tools that have URL-like parameters in their input schema.
   */
  private findUrlTools(
    tools: ToolInfo[]
  ): Array<{ tool: ToolInfo; paramName: string }> {
    const urlTools: Array<{ tool: ToolInfo; paramName: string }> = [];

    for (const tool of tools) {
      const properties =
        (tool.inputSchema as Record<string, unknown>)?.properties as
          | Record<string, unknown>
          | undefined;

      if (!properties) continue;

      for (const paramName of Object.keys(properties)) {
        if (URL_PARAM_PATTERNS.test(paramName)) {
          urlTools.push({ tool, paramName });
          break; // One URL param per tool is enough to flag it
        }
      }
    }

    return urlTools;
  }

  /**
   * Probe a single tool with SSRF payloads and analyze responses.
   */
  private async probeToolForSsrf(
    tool: ToolInfo,
    paramName: string,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const successfulProbes: Array<{
      payload: string;
      category: string;
      description: string;
      response: string;
    }> = [];

    // Group probes by category — only need one success per category
    const probesByCategory = new Map<string, typeof SSRF_PROBES>();
    for (const probe of SSRF_PROBES) {
      const list = probesByCategory.get(probe.category) ?? [];
      list.push(probe);
      probesByCategory.set(probe.category, list);
    }

    for (const [, probes] of probesByCategory) {
      let categoryHit = false;

      for (const probe of probes) {
        if (categoryHit) break; // One hit per category is enough

        try {
          if (verbose) {
            console.error(
              `[vs-mcpaudit:ssrf] Probing ${tool.name}.${paramName} with ${probe.description}: ${probe.payload}`
            );
          }

          const result = await callTool(tool.name, {
            [paramName]: probe.payload,
          });

          // Analyze the response
          const responseStr =
            typeof result === "string"
              ? result
              : JSON.stringify(result);

          const isSuccessful = this.analyzeResponse(responseStr, probe);

          if (isSuccessful) {
            categoryHit = true;
            successfulProbes.push({
              payload: probe.payload,
              category: probe.category,
              description: probe.description,
              response: responseStr.substring(0, 500), // Truncate for evidence
            });
          }
        } catch (err) {
          // Tool call errors are expected for blocked probes
          if (verbose) {
            console.error(
              `[vs-mcpaudit:ssrf] Probe blocked (expected): ${probe.description} → ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      }
    }

    // Generate findings from successful probes
    if (successfulProbes.length === 0) {
      checks.push({
        id: `SSRF-010-${tool.name}`,
        name: `SSRF probing: ${tool.name}`,
        status: CheckStatus.PASS,
        message: "All SSRF probes blocked or rejected",
      });
    } else {
      // Determine severity based on what category succeeded
      const categories = new Set(successfulProbes.map((p) => p.category));
      let severity = Severity.MEDIUM;

      if (categories.has("cloud-metadata")) {
        severity = Severity.CRITICAL;
      } else if (categories.has("loopback") || categories.has("internal-network")) {
        severity = Severity.HIGH;
      } else if (categories.has("protocol-smuggling")) {
        severity = Severity.HIGH;
      } else if (categories.has("bypass")) {
        severity = Severity.HIGH;
      }

      checks.push({
        id: `SSRF-010-${tool.name}`,
        name: `SSRF probing: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `${successfulProbes.length} SSRF probe(s) succeeded across ${categories.size} category(ies)`,
        finding: {
          id: `SSRF-010-${tool.name}`,
          module: this.id,
          severity,
          title: `SSRF vulnerability in tool "${tool.name}"`,
          description:
            `Tool "${tool.name}" accepted and processed ${successfulProbes.length} SSRF probe payload(s). ` +
            `Affected categories: ${[...categories].join(", ")}. ` +
            (categories.has("cloud-metadata")
              ? "CRITICAL: Cloud metadata endpoint was accessible, which may allow credential theft."
              : "The server does not properly validate URL inputs to prevent internal network access."),
          evidence: {
            toolName: tool.name,
            paramName,
            successfulProbes: successfulProbes.map((p) => ({
              payload: p.payload,
              category: p.category,
              description: p.description,
              // Don't include full response in evidence to avoid leaking sensitive data
              responseLength: p.response.length,
            })),
          },
          remediation:
            "Implement comprehensive URL validation: " +
            "(1) Block private/reserved IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16). " +
            "(2) Allowlist URL schemes (https:// only). " +
            "(3) Resolve DNS before fetching and validate the resolved IP. " +
            "(4) Block cloud metadata endpoints. " +
            "(5) Use a URL allowlist if possible.",
          toolName: tool.name,
          cweId: "CWE-918",
        },
      });
    }

    return checks;
  }

  /**
   * Analyze a tool response to determine if an SSRF probe was successful.
   * A successful probe means the server resolved/fetched the target.
   */
  private analyzeResponse(
    response: string,
    probe: (typeof SSRF_PROBES)[number]
  ): boolean {
    const lowerResponse = response.toLowerCase();

    // If the response contains an error about the probe being blocked, it's NOT successful
    const blockedPatterns = [
      "blocked",
      "denied",
      "forbidden",
      "not allowed",
      "invalid url",
      "url validation",
      "private ip",
      "internal address",
      "ssrf",
      "security",
      "restricted",
    ];

    for (const pattern of blockedPatterns) {
      if (lowerResponse.includes(pattern)) {
        return false;
      }
    }

    // Category-specific success indicators
    switch (probe.category) {
      case "cloud-metadata":
        // AWS metadata response patterns
        return (
          lowerResponse.includes("ami-id") ||
          lowerResponse.includes("instance-id") ||
          lowerResponse.includes("security-credentials") ||
          lowerResponse.includes("computemetadata") ||
          lowerResponse.includes("instance/") ||
          (response.length > 50 && !lowerResponse.includes("error"))
        );

      case "loopback":
      case "internal-network":
      case "bypass":
        // Any substantial response that's not an error suggests resolution
        return (
          response.length > 20 &&
          !lowerResponse.includes("error") &&
          !lowerResponse.includes("econnrefused") &&
          !lowerResponse.includes("timeout") &&
          !lowerResponse.includes("enotfound")
        );

      case "protocol-smuggling":
        // file:// protocol success indicators
        if (probe.payload.startsWith("file://")) {
          return (
            lowerResponse.includes("root:") || // /etc/passwd content
            lowerResponse.includes("/bin/") ||
            (response.length > 10 && !lowerResponse.includes("error"))
          );
        }
        // gopher:// success — any non-error response
        return response.length > 10 && !lowerResponse.includes("error");

      default:
        return false;
    }
  }
}
