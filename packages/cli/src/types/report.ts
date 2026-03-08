import type { CheckResult, Finding, Severity } from "./finding.js";

/**
 * Information about an MCP tool exposed by the server.
 */
export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    title?: string;
  };
}

/**
 * Information about an MCP resource exposed by the server.
 */
export interface ResourceInfo {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

/**
 * Information about an MCP prompt exposed by the server.
 */
export interface PromptInfo {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

/**
 * Capabilities discovered from the MCP server.
 */
export interface ServerCapabilities {
  /** Server identification */
  serverInfo: {
    name: string;
    version: string;
  };
  /** Protocol version negotiated */
  protocolVersion: string;
  /** Capabilities declared by the server */
  capabilities: Record<string, unknown>;
  /** All tools exposed by the server */
  tools: ToolInfo[];
  /** All resources exposed by the server */
  resources: ResourceInfo[];
  /** All prompts exposed by the server */
  prompts: PromptInfo[];
}

/**
 * Summary statistics for a scan report.
 */
export interface ReportSummary {
  /** Total number of checks run */
  totalChecks: number;
  /** Checks passed */
  passed: number;
  /** Checks with warnings */
  warnings: number;
  /** Checks failed */
  failed: number;
  /** Checks skipped */
  skipped: number;
  /** Checks errored */
  errors: number;
  /** Count of findings by severity */
  findingsBySeverity: Record<Severity, number>;
  /** Security score (0-100) */
  securityScore: number;
}

/**
 * Module execution result within a report.
 */
export interface ModuleResult {
  /** Module identifier */
  moduleId: string;
  /** Module name */
  moduleName: string;
  /** Module version */
  moduleVersion: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Check results from this module */
  checks: CheckResult[];
  /** Findings from this module */
  findings: Finding[];
  /** Error if the module crashed */
  error?: string;
}

/**
 * Transport configuration used for the scan.
 */
export interface TransportConfig {
  type: "stdio" | "streamable-http";
  command?: string;
  args?: string[];
  url?: string;
}

/**
 * Complete scan report.
 */
export interface ScanReport {
  /** Report version for forward compatibility */
  version: "1.0.0";
  /** Unique report identifier */
  id: string;
  /** Timestamp of the scan (ISO 8601) */
  timestamp: string;
  /** Duration of the entire scan in milliseconds */
  durationMs: number;
  /** vs-mcpaudit CLI version */
  cliVersion: string;
  /** Transport configuration used */
  transport: TransportConfig;
  /** Server capabilities discovered */
  server: ServerCapabilities;
  /** Results from each module */
  modules: ModuleResult[];
  /** All findings aggregated */
  findings: Finding[];
  /** Report summary and score */
  summary: ReportSummary;
}
