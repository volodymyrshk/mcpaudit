import ora from "ora";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { MCPClientEngine } from "../core/mcp-client.js";
import { ModuleRunner } from "../core/module-runner.js";
import { calculateScore } from "../core/scorer.js";
import { outputReport, type OutputFormat } from "../core/reporter.js";
import { toSarif } from "../core/sarif.js";
import { ToolPermissionsModule } from "../modules/tool-permissions.js";
import { TransportSecurityModule } from "../modules/transport-security.js";
import { SsrfDetectionModule } from "../modules/ssrf-detection.js";
import { SchemaManipulationModule } from "../modules/schema-manipulation.js";
import { ContextExtractionModule } from "../modules/context-extraction.js";
import type { AuditModule, ScanReport, TransportConfig } from "../types/index.js";

const CLI_VERSION = "0.1.0-alpha.1";

export interface ScanOptions {
  /** Server command string (e.g., "npx -y @modelcontextprotocol/server-filesystem /tmp") */
  server: string;
  /** Transport type */
  transport: "stdio" | "streamable-http";
  /** Output format */
  format: OutputFormat;
  /** Enable active scanning modules */
  active: boolean;
  /** Run specific modules only */
  modules?: string[];
  /** Verbose output */
  verbose: boolean;
  /** Connection timeout in ms */
  timeout: number;
  /** Output file path for saving the report */
  output?: string;
}

/**
 * Parse a server command string into command and args.
 * Handles quoted strings properly.
 */
function parseServerCommand(serverStr: string): { command: string; args: string[] } {
  const parts: string[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (const char of serverStr) {
    if (inQuote) {
      if (char === quoteChar) {
        inQuote = false;
      } else {
        current += char;
      }
    } else if (char === '"' || char === "'") {
      inQuote = true;
      quoteChar = char;
    } else if (char === " ") {
      if (current) {
        parts.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }

  if (current) {
    parts.push(current);
  }

  if (parts.length === 0) {
    throw new Error("Empty server command");
  }

  return {
    command: parts[0],
    args: parts.slice(1),
  };
}

/**
 * Get all available audit modules.
 */
function getAvailableModules(): AuditModule[] {
  return [
    new ToolPermissionsModule(),
    new TransportSecurityModule(),
    new SchemaManipulationModule(),
    new ContextExtractionModule(),
    new SsrfDetectionModule(),
  ];
}

/**
 * Execute a security scan against an MCP server.
 */
export async function executeScan(options: ScanOptions): Promise<void> {
  const startTime = performance.now();
  const engine = new MCPClientEngine();
  const isTerminal = options.format === "terminal";

  // Only show spinners/progress in terminal mode
  const spinner = isTerminal ? ora() : null;

  try {
    // ── Step 1: Connect to MCP server ──────────────────────────────────
    spinner?.start("Connecting to MCP server...");

    const { command, args } = parseServerCommand(options.server);

    const capabilities = await engine.connect({
      command,
      args,
      timeoutMs: options.timeout,
      verbose: options.verbose,
    });

    spinner?.succeed(
      `Connected to ${capabilities.serverInfo.name} v${capabilities.serverInfo.version} ` +
        `(${capabilities.tools.length} tools, ${capabilities.resources.length} resources, ${capabilities.prompts.length} prompts)`
    );

    // ── Step 2: Select modules ─────────────────────────────────────────
    let modules = getAvailableModules();

    // Filter by requested modules
    if (options.modules && options.modules.length > 0) {
      const requestedIds = new Set(options.modules);
      modules = modules.filter((m) => requestedIds.has(m.id));
      if (modules.length === 0) {
        throw new Error(
          `No matching modules found. Available: ${getAvailableModules()
            .map((m) => m.id)
            .join(", ")}`
        );
      }
    }

    // ── Step 3: Run modules ────────────────────────────────────────────
    spinner?.start(`Running ${modules.length} audit module(s)...`);

    const runner = new ModuleRunner();
    const moduleResults = await runner.run({
      capabilities,
      modules,
      callTool: options.active
        ? (name, args) => engine.callTool(name, args)
        : undefined,
      activeMode: options.active,
      verbose: options.verbose,
      onProgress: (moduleId, status) => {
        if (isTerminal) {
          switch (status) {
            case "start":
              spinner?.start(`Running module: ${moduleId}...`);
              break;
            case "complete":
              spinner?.succeed(`Module complete: ${moduleId}`);
              break;
            case "error":
              spinner?.fail(`Module error: ${moduleId}`);
              break;
          }
        }
      },
    });

    // ── Step 4: Calculate score and build report ───────────────────────
    const summary = calculateScore(moduleResults);
    const allFindings = moduleResults.flatMap((r) => r.findings);
    const durationMs = Math.round(performance.now() - startTime);

    const transportConfig: TransportConfig = {
      type: options.transport,
      command,
      args,
    };

    const report: ScanReport = {
      version: "1.0.0",
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      durationMs,
      cliVersion: CLI_VERSION,
      transport: transportConfig,
      server: capabilities,
      modules: moduleResults,
      findings: allFindings,
      summary,
    };

    // ── Step 5: Output report ──────────────────────────────────────────
    outputReport(report, options.format);

    // ── Step 6: Save to file if --output specified ─────────────────────
    if (options.output) {
      const outputPath = options.output;
      let fileContent: string;

      if (outputPath.endsWith(".sarif") || outputPath.endsWith(".sarif.json")) {
        fileContent = JSON.stringify(toSarif(report), null, 2);
      } else {
        fileContent = JSON.stringify(report, null, 2);
      }

      writeFileSync(outputPath, fileContent, "utf-8");

      if (isTerminal) {
        console.log(`  Report saved to: ${outputPath}\n`);
      }
    }

    // ── Step 7: Exit code based on findings ────────────────────────────
    if (summary.findingsBySeverity.CRITICAL > 0) {
      process.exitCode = 3;
    } else if (summary.failed > 0) {
      process.exitCode = 2;
    } else if (summary.warnings > 0) {
      process.exitCode = 1;
    }
  } catch (err) {
    spinner?.fail("Scan failed");
    const message = err instanceof Error ? err.message : String(err);
    if (options.format === "json") {
      console.log(JSON.stringify({ error: message }, null, 2));
    } else {
      console.error(`\n  Error: ${message}\n`);
    }
    process.exitCode = 4;
  } finally {
    await engine.disconnect();
  }
}
