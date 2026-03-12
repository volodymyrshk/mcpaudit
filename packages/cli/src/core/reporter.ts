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

// ─── ASCII Art Logo ──────────────────────────────────────────────────────────

const LOGO = `
 /$$      /$$  /$$$$$$  /$$$$$$$         /$$$$$$                  /$$ /$$   /$$
| $$$    /$$$ /$$__  $$| $$__  $$       /$$__  $$                | $$|__/  | $$
| $$$$  /$$$$| $$  \\__/| $$  \\ $$      | $$  \\ $$ /$$   /$$  /$$$$$$$ /$$ /$$$$$$
| $$ $$/$$ $$| $$      | $$$$$$$/      | $$$$$$$$| $$  | $$ /$$__  $$| $$|_  $$_/
| $$  $$$| $$| $$      | $$____/       | $$__  $$| $$  | $$| $$  | $$| $$  | $$
| $$\\  $ | $$| $$    $$| $$            | $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$
| $$ \\/  | $$|  $$$$$$/| $$            | $$  | $$|  $$$$$$/|  $$$$$$$| $$  |  $$$$/
|__/     |__/ \\______/ |__/            |__/  |__/ \\______/  \\_______/|__/   \\___/
`;

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

  // Logo & Header
  console.log(chalk.cyan(LOGO));
  console.log(chalk.dim("  ── MCP Server Security Scanner ──────────────────────────────────────────────"));
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

  // Compliance mapping
  outputCompliance(report);

  // Security score gauge
  outputScore(summary.securityScore, summary);

  // Traction footer
  outputFooter();
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
}

function outputCompliance(report: ScanReport): void {
  const compliance = report.compliance;
  if (!compliance) return;

  console.log(chalk.bold("  Compliance Mapping:"));
  console.log(chalk.dim("  ─".repeat(30)));
  console.log();

  // NIST SP 800-171
  if (Object.keys(compliance.nist).length > 0) {
    console.log(chalk.bold("  NIST SP 800-171:"));
    for (const [control, count] of Object.entries(compliance.nist).sort((a, b) => b[1] - a[1])) {
      console.log(chalk.cyan(`    ${control}`) + chalk.dim(` (${count} finding${count > 1 ? "s" : ""})`));
    }
    console.log();
  }

  // SOC 2 TSC
  if (Object.keys(compliance.soc2).length > 0) {
    console.log(chalk.bold("  SOC 2 TSC:"));
    for (const [control, count] of Object.entries(compliance.soc2).sort((a, b) => b[1] - a[1])) {
      console.log(chalk.yellow(`    ${control}`) + chalk.dim(` (${count} finding${count > 1 ? "s" : ""})`));
    }
    console.log();
  }

  // OWASP ASVS
  if (Object.keys(compliance.asvs).length > 0) {
    console.log(chalk.bold("  OWASP ASVS v4.0:"));
    for (const [control, count] of Object.entries(compliance.asvs).sort((a, b) => b[1] - a[1])) {
      console.log(chalk.magenta(`    ${control}`) + chalk.dim(` (${count} finding${count > 1 ? "s" : ""})`));
    }
    console.log();
  }

  console.log(
    chalk.dim(`  ${compliance.mappedFindings} finding(s) mapped, ${compliance.unmappedFindings} unmapped`)
  );
  console.log();
}

function outputScore(score: number, summary: ScanReport["summary"]): void {
  const grade = scoreToGrade(score);
  const color = scoreToColor(score);
  const colorFn =
    color === "green" ? chalk.green : color === "yellow" ? chalk.yellow : chalk.red;

  // Score header
  console.log(chalk.bold("  Security Score"));
  console.log();

  // Visual gauge bar (30 chars wide)
  const BAR_WIDTH = 30;
  const filled = Math.round((score / 100) * BAR_WIDTH);
  const empty = BAR_WIDTH - filled;
  const bar = colorFn("█".repeat(filled)) + chalk.dim("░".repeat(empty));
  const scoreDisplay = colorFn.bold(`${score}/100`);
  const gradeDisplay = colorFn.bold(`Grade: ${grade}`);

  console.log(`    ${bar}  ${scoreDisplay}  ${gradeDisplay}`);
  console.log();

  // Inline severity summary
  const s = summary.findingsBySeverity;
  const parts = [
    chalk.red(`  CRITICAL: ${s[Severity.CRITICAL]}`),
    chalk.red(`  HIGH: ${s[Severity.HIGH]}`),
    chalk.yellow(`  WARN: ${summary.warnings}`),
    chalk.green(`  PASS: ${summary.passed}`),
  ];
  console.log(`  ` + parts.join("  "));
}

function outputFooter(): void {
  console.log();
  console.log(chalk.dim("  ─────────────────────────────────────────────────────────────────────────────"));
  console.log(chalk.bold("  Secured your MCP setup? Share your scorecard!"));
  console.log(chalk.cyan("  github.com/vs-mcpaudit/vs-mcpaudit"));
  console.log();
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
