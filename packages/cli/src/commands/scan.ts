import ora from "ora";
import chalk from "chalk";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { MCPClientEngine } from "../core/mcp-client.js";
import { ModuleRunner } from "../core/module-runner.js";
import { calculateScore } from "../core/scorer.js";
import { outputReport, type OutputFormat, type OutputOptions } from "../core/reporter.js";
import { toSarif } from "../core/sarif.js";
import { ToolPermissionsModule } from "../modules/tool-permissions.js";
import { TransportSecurityModule } from "../modules/transport-security.js";
import { SsrfDetectionModule } from "../modules/ssrf-detection.js";
import { ActiveFuzzerModule } from "../modules/active-fuzzer.js";
import { SchemaManipulationModule } from "../modules/schema-manipulation.js";
import { ContextExtractionModule } from "../modules/context-extraction.js";
import { SecretLeakDetectionModule } from "../modules/secret-leak-detection.js";
import { ResourcePromptAuditModule } from "../modules/resource-prompt-audit.js";
import { ToolShadowingModule } from "../modules/tool-shadowing.js";
import { ResponseFingerprintingModule } from "../modules/response-fingerprinting.js";
import { AuthBoundaryTestingModule } from "../modules/auth-boundary-testing.js";
import { SupplyChainAnalysisModule } from "../modules/supply-chain-analysis.js";
import { enrichFindings, generateComplianceSummary } from "../compliance/compliance-enricher.js";
import { TuiDashboard } from "../core/tui-dashboard.js";
import { generateFixSuggestions, outputFixSuggestions } from "../core/autofix.js";
import { generateExecutiveSummary, outputExecutiveSummary } from "../core/executive-summary.js";
import { loadRules, evaluateRules, outputRuleResults } from "../core/rules-engine.js";
import { CheckStatus } from "../types/index.js";
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
  /** Compliance frameworks to map (nist, soc2, asvs, or all) */
  compliance?: string[];
  /** Timeout per active probe in ms */
  probeTimeout?: number;
  /** Delay between active probes in ms */
  probeDelay?: number;
  /** Minimum severity to display (CRITICAL, HIGH, MEDIUM, LOW, INFO) */
  minSeverity?: string;
  /** Custom payloads for active fuzzing */
  customPayloads?: Array<{ value: string; label: string }>;
  /** Finding IDs to ignore (baseline) */
  ignoreList?: Set<string>;
  /** Enable interactive TUI dashboard */
  tui?: boolean;
  /** Show auto-fix suggestions after report */
  autofix?: boolean;
  /** Show executive summary for non-technical stakeholders */
  executiveSummary?: boolean;
  /** Path to custom policy rules file (YAML or JSON) */
  rules?: string;
  /** Fail if security score is below this threshold (0-100) */
  failBelow?: number;
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
    new SecretLeakDetectionModule(),
    new ResourcePromptAuditModule(),
    new SsrfDetectionModule(),
    new ActiveFuzzerModule(),
    new ToolShadowingModule(),
    new ResponseFingerprintingModule(),
    new AuthBoundaryTestingModule(),
    new SupplyChainAnalysisModule(),
  ];
}

/**
 * Execute a security scan against an MCP server.
 */
export async function executeScan(options: ScanOptions): Promise<ScanReport | void> {
  const startTime = performance.now();
  const engine = new MCPClientEngine();
  const isTerminal = options.format === "terminal";
  const useTui = isTerminal && options.tui === true;

  // Only show spinners/progress in terminal mode (unless TUI is active)
  const spinner = isTerminal && !useTui ? ora() : null;
  const dashboard = useTui ? new TuiDashboard() : null;

  try {
    // ── Step 1: Connect to MCP server
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

    // ── Step 2 Select modules
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

    // ── Step 3: Run modules
    spinner?.start(`Running ${modules.length} audit module(s)...`);
    dashboard?.init(modules);

    const runner = new ModuleRunner();
    const moduleResults = await runner.run({
      capabilities,
      modules,
      callTool: options.active
        ? (name, args) => engine.callTool(name, args)
        : undefined,
      activeMode: options.active,
      verbose: options.verbose,
      probeTimeout: options.probeTimeout,
      probeDelay: options.probeDelay,
      customPayloads: options.customPayloads,
      onProgress: (moduleId, status, result) => {
        if (dashboard) {
          switch (status) {
            case "start":
              dashboard.onModuleStart(moduleId);
              break;
            case "complete":
            case "error":
              if (result) dashboard.onModuleComplete(moduleId, result);
              break;
          }
        } else if (isTerminal) {
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
      onDetailProgress: (message) => {
        if (dashboard) {
          dashboard.onDetailProgress(message);
        } else if (isTerminal) {
          spinner?.start(message);
        }
      },
    });

    // ── Step 3b: Evaluate custom policy rules (if --rules specified)
    let ruleResults: ReturnType<typeof evaluateRules> = [];
    if (options.rules) {
      spinner?.start("Evaluating custom policy rules...");
      const rules = loadRules(options.rules);
      ruleResults = evaluateRules(rules, capabilities);

      // Inject rule violations as findings into module results
      const ruleFindings = ruleResults
        .filter((r) => r.finding)
        .map((r) => r.finding!);

      if (ruleFindings.length > 0) {
        moduleResults.push({
          moduleId: "custom-rules",
          moduleName: "Custom Policy Rules",
          moduleVersion: "1.0.0",
          checks: ruleResults,
          findings: ruleFindings,
          durationMs: 0,
        });
      }

      spinner?.succeed(
        `Policy rules: ${ruleResults.filter((r) => r.status === CheckStatus.PASS).length} passed, ` +
        `${ruleResults.filter((r) => r.status === CheckStatus.FAIL).length} failed`
      );
    }

    // ── Step 4: Calculate score and build report
    const summary = calculateScore(moduleResults);
    let allFindings = moduleResults.flatMap((r) => r.findings);
    const durationMs = Math.round(performance.now() - startTime);

    // ── Step 4a: Filter ignored findings
    if (options.ignoreList && options.ignoreList.size > 0) {
      allFindings = allFindings.filter((f) => !options.ignoreList!.has(f.id));
    }

    // ── Step 4b: Compliance enrichment (if --compliance flag set)
    let enrichedFindings = allFindings;
    let complianceSummary;
    if (options.compliance && options.compliance.length > 0) {
      enrichedFindings = enrichFindings(allFindings);
      complianceSummary = generateComplianceSummary(enrichedFindings);
    }

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
      findings: enrichedFindings,
      summary,
      ...(complianceSummary ? { compliance: complianceSummary } : {}),
    };

    // ── Step 5: Finalize TUI dashboard with score reveal
    if (dashboard) {
      dashboard.finalize(summary);
    }

    // ── Step 5a: Output report
    outputReport(report, options.format, { minSeverity: options.minSeverity });

    // ── Step 5b: Executive summary (terminal only)
    if (isTerminal && options.executiveSummary) {
      const execSummary = generateExecutiveSummary(report);
      outputExecutiveSummary(execSummary);
    }

    // ── Step 5c: Auto-fix suggestions (terminal only)
    if (isTerminal && options.autofix) {
      const fixes = generateFixSuggestions(report);
      outputFixSuggestions(fixes);
    }

    // ── Step 5d: Custom policy rule results (terminal only)
    if (isTerminal && ruleResults.length > 0) {
      outputRuleResults(ruleResults);
    }

    // ── Step 6: Save to file if --output specified
    if (options.output) {
      const outputPath = options.output;
      let fileContent: string;

      if (outputPath.endsWith(".sarif") || outputPath.endsWith(".sarif.json")) {
        fileContent = JSON.stringify(toSarif(report), null, 2);
      } else if (outputPath.endsWith(".md")) {
        // Save markdown by temporarily switching format
        const origLog = console.log;
        let md = "";
        console.log = (msg: string) => { md += msg + "\n"; };
        outputReport(report, "markdown");
        console.log = origLog;
        fileContent = md;
      } else {
        fileContent = JSON.stringify(report, null, 2);
      }

      writeFileSync(outputPath, fileContent, "utf-8");

      if (isTerminal) {
        console.log(`  Report saved to: ${outputPath}\n`);
      }
    }

    // ── Step 7 - Exit code based on findings
    if (options.failBelow !== undefined && summary.securityScore < options.failBelow) {
      if (isTerminal) {
        console.log(
          chalk.red(`\n  ✗ Score ${summary.securityScore}/100 is below threshold ${options.failBelow}/100\n`)
        );
      }
      process.exitCode = 5;
    } else if (summary.findingsBySeverity.CRITICAL > 0) {
      process.exitCode = 3;
    } else if (summary.failed > 0) {
      process.exitCode = 2;
    } else if (summary.warnings > 0) {
      process.exitCode = 1;
    }

    // Return report for library/API mode
    return report;
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
