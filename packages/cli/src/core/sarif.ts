import { Severity, type ScanReport, type Finding } from "../types/index.js";

/**
 * SARIF (Static Analysis Results Interchange Format) v2.1.0 output.
 *
 * Enables integration with:
 * - GitHub Code Scanning (upload via `github/codeql-action/upload-sarif`)
 * - VS Code SARIF Viewer extension
 * - Azure DevOps
 * - Any SARIF-compatible security dashboard
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const CLI_VERSION = "0.1.0-alpha.1";
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: Array<{
    physicalLocation?: {
      artifactLocation: { uri: string; uriBaseId?: string };
    };
    logicalLocations?: Array<{
      name: string;
      kind: string;
      fullyQualifiedName?: string;
    }>;
  }>;
  fixes?: Array<{
    description: { text: string };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  help?: { text: string; markdown?: string };
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
  properties?: Record<string, unknown>;
}

interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    invocations: Array<{
      executionSuccessful: boolean;
      startTimeUtc?: string;
      endTimeUtc?: string;
      properties?: Record<string, unknown>;
    }>;
    properties?: Record<string, unknown>;
  }>;
}

/**
 * Map AgentAudit severity to SARIF level.
 */
function severityToLevel(
  severity: Severity
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case Severity.CRITICAL:
      return "error";
    case Severity.HIGH:
      return "error";
    case Severity.MEDIUM:
      return "warning";
    case Severity.LOW:
      return "note";
    case Severity.INFO:
      return "none";
  }
}

/**
 * Convert an AgentAudit ScanReport to SARIF v2.1.0 format.
 */
export function toSarif(report: ScanReport): SarifLog {
  // Build unique rules from findings
  const ruleMap = new Map<string, SarifRule>();
  const ruleIndexMap = new Map<string, number>();

  for (const finding of report.findings) {
    if (!ruleMap.has(finding.id)) {
      const ruleIndex = ruleMap.size;
      ruleIndexMap.set(finding.id, ruleIndex);
      ruleMap.set(finding.id, {
        id: finding.id,
        name: finding.title.replace(/[^a-zA-Z0-9]/g, ""),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: {
          text: finding.remediation,
          markdown: `**Remediation:** ${finding.remediation}`,
        },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          severity: finding.severity,
          module: finding.module,
          ...(finding.cweId ? { "security-severity": cweToScore(finding.cweId) } : {}),
          tags: [
            "security",
            "mcp",
            finding.module,
            ...(finding.cweId ? [finding.cweId] : []),
          ],
        },
      });
    }
  }

  // Build results from findings
  const results: SarifResult[] = report.findings.map((finding) => ({
    ruleId: finding.id,
    ruleIndex: ruleIndexMap.get(finding.id) ?? 0,
    level: severityToLevel(finding.severity),
    message: {
      text: `${finding.title}: ${finding.description}`,
    },
    locations: [
      {
        logicalLocations: [
          {
            name: finding.toolName ?? report.server.serverInfo.name,
            kind: finding.toolName ? "mcpTool" : "mcpServer",
            fullyQualifiedName: finding.toolName
              ? `${report.server.serverInfo.name}/${finding.toolName}`
              : report.server.serverInfo.name,
          },
        ],
      },
    ],
    fixes: [
      {
        description: { text: finding.remediation },
      },
    ],
    properties: {
      severity: finding.severity,
      module: finding.module,
      evidence: finding.evidence,
    },
  }));

  // Calculate end time from start + duration
  const startTime = new Date(report.timestamp);
  const endTime = new Date(startTime.getTime() + report.durationMs);

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentAudit",
            version: report.cliVersion,
            informationUri: "https://github.com/agentaudit/agentaudit",
            rules: [...ruleMap.values()],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.timestamp,
            endTimeUtc: endTime.toISOString(),
            properties: {
              serverName: report.server.serverInfo.name,
              serverVersion: report.server.serverInfo.version,
              protocolVersion: report.server.protocolVersion,
              toolCount: report.server.tools.length,
              securityScore: report.summary.securityScore,
            },
          },
        ],
        properties: {
          securityScore: report.summary.securityScore,
          totalChecks: report.summary.totalChecks,
          transport: report.transport,
        },
      },
    ],
  };
}

/**
 * Map CWE IDs to approximate security-severity scores (0-10).
 * Used by GitHub Code Scanning to prioritize results.
 */
function cweToScore(cweId: string): string {
  const scores: Record<string, string> = {
    "CWE-918": "9.0", // SSRF
    "CWE-78": "9.8", // OS Command Injection
    "CWE-89": "9.8", // SQL Injection
    "CWE-22": "7.5", // Path Traversal
    "CWE-79": "6.1", // XSS
    "CWE-200": "5.3", // Information Exposure
    "CWE-732": "5.3", // Incorrect Permission Assignment
  };
  return scores[cweId] ?? "5.0";
}
