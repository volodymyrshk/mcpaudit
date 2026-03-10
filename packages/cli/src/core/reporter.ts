import chalk from "chalk";
import Table from "cli-table3";
import {
  Severity,
  CheckStatus,
  type ScanReport,
  type Finding,
  type CheckResult,
  type ModuleResult,
} from "../types/index.js";
import { scoreToGrade, scoreToColor } from "./scorer.js";

export type OutputFormat = "terminal" | "json";

/**
 * Format and output a scan report.
 */
export function outputReport(report: ScanReport, format: OutputFormat): void {
  switch (format) {
    case "json":
      outputJson(report);
      break;
    case "terminal":
    default:
      outputTerminal(report);
      break;
  }
}

// ─── JSON Output ───────────────────────────────────────────────────────────────

function outputJson(report: ScanReport): void {
  // Clean JSON output to stdout (no ANSI codes, no extra text)
  console.log(JSON.stringify(report, null, 2));
}

// ─── Terminal Output ───────────────────────────────────────────────────────────

function outputTerminal(report: ScanReport): void {
  const { server, modules, summary } = report;

  // Header
  console.log();
  console.log(chalk.bold.cyan("  vs-mcpaudit Security Report"));
  console.log(chalk.dim("  ─".repeat(30)));
  console.log();

  // Server info
  console.log(chalk.bold("  Server: ") + `${server.serverInfo.name} v${server.serverInfo.version}`);
  console.log(chalk.bold("  Protocol: ") + server.protocolVersion);
  console.log(
    chalk.bold("  Capabilities: ") +
    `${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts`
  );
  console.log(chalk.bold("  Scan Duration: ") + `${report.durationMs}ms`);
  console.log();

  // Module results
  for (const modResult of modules) {
    outputModuleResult(modResult);
  }

  // Summary
  outputSummary(summary);

  // Security score
  outputScore(summary.securityScore);
  console.log();
}

function outputModuleResult(result: ModuleResult): void {
  const icon = result.error ? chalk.red("✗") : chalk.green("✓");
  console.log(`  ${icon} ${chalk.bold(result.moduleName)} ${chalk.dim(`v${result.moduleVersion} (${result.durationMs}ms)`)}`);

  if (result.error) {
    console.log(chalk.red(`    Error: ${result.error}`));
    console.log();
    return;
  }

  for (const check of result.checks) {
    const badge = statusBadge(check.status);
    const msg = check.message ? chalk.dim(` — ${check.message}`) : "";
    console.log(`    ${badge} ${check.name}${msg}`);
  }
  console.log();
}

function statusBadge(status: CheckStatus): string {
  switch (status) {
    case CheckStatus.PASS:
      return chalk.bgGreen.black(" PASS ");
    case CheckStatus.WARN:
      return chalk.bgYellow.black(" WARN ");
    case CheckStatus.FAIL:
      return chalk.bgRed.white(" FAIL ");
    case CheckStatus.SKIP:
      return chalk.bgGray.white(" SKIP ");
    case CheckStatus.ERROR:
      return chalk.bgMagenta.white(" ERR  ");
  }
}

function outputSummary(summary: typeof ScanReport.prototype extends never ? never : ScanReport["summary"]): void {
  console.log(chalk.dim("  ─".repeat(30)));
  console.log();

  const table = new Table({
    chars: {
      top: "", "top-mid": "", "top-left": "", "top-right": "",
      bottom: "", "bottom-mid": "", "bottom-left": "", "bottom-right": "",
      left: "  │", "left-mid": "", mid: "", "mid-mid": "",
      right: "│", "right-mid": "", middle: " │ ",
    },
    style: { "padding-left": 1, "padding-right": 1 },
  });

  table.push(
    [chalk.bold("Total Checks"), String(summary.totalChecks)],
    [chalk.green("Passed"), String(summary.passed)],
    [chalk.yellow("Warnings"), String(summary.warnings)],
    [chalk.red("Failed"), String(summary.failed)],
    [chalk.gray("Skipped"), String(summary.skipped)]
  );

  console.log(table.toString());
  console.log();

  // Findings breakdown
  if (
    summary.findingsBySeverity[Severity.CRITICAL] > 0 ||
    summary.findingsBySeverity[Severity.HIGH] > 0
  ) {
    console.log(chalk.bold("  Findings:"));
    if (summary.findingsBySeverity[Severity.CRITICAL] > 0) {
      console.log(
        chalk.red(`    ${summary.findingsBySeverity[Severity.CRITICAL]} CRITICAL`)
      );
    }
    if (summary.findingsBySeverity[Severity.HIGH] > 0) {
      console.log(
        chalk.red(`    ${summary.findingsBySeverity[Severity.HIGH]} HIGH`)
      );
    }
    if (summary.findingsBySeverity[Severity.MEDIUM] > 0) {
      console.log(
        chalk.yellow(`    ${summary.findingsBySeverity[Severity.MEDIUM]} MEDIUM`)
      );
    }
    if (summary.findingsBySeverity[Severity.LOW] > 0) {
      console.log(
        chalk.dim(`    ${summary.findingsBySeverity[Severity.LOW]} LOW`)
      );
    }
    console.log();
  }
}

function outputScore(score: number): void {
  const grade = scoreToGrade(score);
  const color = scoreToColor(score);
  const colorFn =
    color === "green" ? chalk.green : color === "yellow" ? chalk.yellow : chalk.red;

  const scoreDisplay = colorFn.bold(`${score}/100`);
  const gradeDisplay = colorFn.bold(grade);

  console.log(`  Security Score: ${scoreDisplay} (Grade: ${gradeDisplay})`);
}

/**
 * Format findings for detailed output used in verbose mode.
 */
export function formatFinding(finding: Finding): string {
  const severityColor = {
    [Severity.CRITICAL]: chalk.bgRed.white,
    [Severity.HIGH]: chalk.red,
    [Severity.MEDIUM]: chalk.yellow,
    [Severity.LOW]: chalk.dim,
    [Severity.INFO]: chalk.blue,
  };

  const lines = [
    `${severityColor[finding.severity](` ${finding.severity} `)} ${chalk.bold(finding.title)}`,
    chalk.dim(`  ID: ${finding.id} | Module: ${finding.module}`),
    `  ${finding.description}`,
  ];

  if (finding.toolName) {
    lines.push(chalk.dim(`  Tool: ${finding.toolName}`));
  }

  lines.push(chalk.green(`  Remediation: ${finding.remediation}`));

  return lines.join("\n");
}
