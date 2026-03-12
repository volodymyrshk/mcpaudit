import type { CheckResult, Finding } from "./finding.js";
import type { ServerCapabilities } from "./report.js";

/**
 * Execution mode for audit modules.
 * - passive: Analyzes schemas/metadata only, no tool calls
 * - active:  Makes tool calls to the server (e.g., SSRF probes)
 */
export type ModuleMode = "passive" | "active";

/**
 * Context provided to each audit module during execution.
 */
export interface ModuleContext {
  /** Full server capabilities manifest */
  capabilities: ServerCapabilities;
  /** MCP client for making tool calls (only used by active modules) */
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  /** Whether active scanning is enabled */
  activeMode: boolean;
  /** Verbose logging enabled */
  verbose: boolean;
  /** Timeout per active probe in ms (default: 5000) */
  probeTimeout?: number;
  /** Delay between active probes in ms (default: 100) */
  probeDelay?: number;
}

/**
 * Abstract interface for all audit modules.
 * Each module implements a specific category of security checks.
 */
export interface AuditModule {
  /** Unique module identifier (e.g., "tool-permissions") */
  id: string;
  /** Human-readable module name */
  name: string;
  /** Short description of what this module checks */
  description: string;
  /** Module version */
  version: string;
  /** Execution mode */
  mode: ModuleMode;

  /**
   * Execute the audit module and return results.
   * @param context - Server capabilities and execution context
   * @returns Array of check results with associated findings
   */
  run(context: ModuleContext): Promise<CheckResult[]>;
}
