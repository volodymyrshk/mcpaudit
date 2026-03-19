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

export type OutputFormat = "terminal" | "json" | "html" | "markdown";

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
 * Print the ASCII banner with optional subtitle.
 * Reusable across all commands for consistent branding.
 */
export function printBanner(subtitle?: string): void {
  console.log(chalk.cyan(LOGO));
  console.log(chalk.dim(`  ── ${subtitle ?? "MCP Server Security Scanner"} ──`));
  console.log();
}

/** Severity rank for filtering */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/** Options for report output */
export interface OutputOptions {
  minSeverity?: string;
}

/**
 * Format and output a scan report.
 */
export function outputReport(report: ScanReport, format: OutputFormat, options?: OutputOptions): void {
  switch (format) {
    case "json":
      outputJson(report);
      break;
    case "html":
      outputHtml(report);
      break;
    case "markdown":
      outputMarkdown(report);
      break;
    case "terminal":
    default:
      outputTerminal(report, options);
      break;
  }
}

// ─── JSON Output ───────────────────────────────────────────────────────────────

function outputJson(report: ScanReport): void {
  // Clean JSON output to stdout (no ANSI codes, no extra text)
  console.log(JSON.stringify(report, null, 2));
}

// ─── Terminal Output ───────────────────────────────────────────────────────────

function outputTerminal(report: ScanReport, options?: OutputOptions): void {
  const { server, modules, summary } = report;
  const minRank = SEVERITY_RANK[options?.minSeverity ?? ""] ?? 0;

  // Logo & Header
  printBanner("MCP Server Security Scanner");

  // Server info
  console.log(chalk.bold("  Server: ") + `${server.serverInfo.name} v${server.serverInfo.version}`);
  console.log(chalk.bold("  Protocol: ") + server.protocolVersion);
  console.log(
    chalk.bold("  Capabilities: ") +
    `${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts`
  );
  console.log(chalk.bold("  Scan Duration: ") + `${report.durationMs}ms`);
  if (minRank > 0) {
    console.log(chalk.dim(`  Filter: showing ${options!.minSeverity} and above`));
  }
  console.log();

  // Module results
  for (const modResult of modules) {
    outputModuleResult(modResult, minRank);
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

function outputModuleResult(result: ModuleResult, minRank: number = 0): void {
  const icon = result.error ? chalk.red("✗") : chalk.green("✓");
  console.log(`  ${icon} ${chalk.bold(result.moduleName)} ${chalk.dim(`v${result.moduleVersion} (${result.durationMs}ms)`)}`);

  if (result.error) {
    console.log(chalk.red(`    Error: ${result.error}`));
    console.log();
    return;
  }

  // Filter checks by minimum severity
  const filteredChecks = minRank > 0
    ? result.checks.filter((check) => {
        if (check.status === CheckStatus.PASS || check.status === CheckStatus.SKIP) return false;
        if (!check.finding) return check.status === CheckStatus.FAIL; // Always show FAILs
        return (SEVERITY_RANK[check.finding.severity] ?? 0) >= minRank;
      })
    : result.checks;

  for (const check of filteredChecks) {
    const badge = statusBadge(check.status);
    const msg = check.message ? chalk.dim(` — ${check.message}`) : "";
    console.log(`    ${badge} ${check.name}${msg}`);
  }

  if (minRank > 0 && filteredChecks.length === 0) {
    console.log(chalk.dim(`    No findings at this severity level`));
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

// ─── Markdown Output ─────────────────────────────────────────────────────────

function outputMarkdown(report: ScanReport): void {
  const { server, modules, summary } = report;
  const score = summary.securityScore;
  const grade = scoreToGrade(score);

  const lines: string[] = [];

  lines.push("# MCP Audit Report");
  lines.push("");
  lines.push(`**Server:** ${server.serverInfo.name} v${server.serverInfo.version}`);
  lines.push(`**Protocol:** ${server.protocolVersion}`);
  lines.push(`**Capabilities:** ${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts`);
  lines.push(`**Scan Duration:** ${report.durationMs}ms`);
  lines.push(`**Date:** ${new Date(report.timestamp).toLocaleString()}`);
  lines.push("");

  // Score
  lines.push("## Security Score");
  lines.push("");
  lines.push(`**${score}/100** (Grade: ${grade})`);
  lines.push("");
  const s = summary.findingsBySeverity;
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Checks | ${summary.totalChecks} |`);
  lines.push(`| Passed | ${summary.passed} |`);
  lines.push(`| Warnings | ${summary.warnings} |`);
  lines.push(`| Failed | ${summary.failed} |`);
  lines.push(`| Critical | ${s.CRITICAL} |`);
  lines.push(`| High | ${s.HIGH} |`);
  lines.push("");

  // Module results
  lines.push("## Module Results");
  lines.push("");

  for (const mod of modules) {
    const icon = mod.error ? "x" : "check";
    lines.push(`### ${mod.error ? "❌" : "✅"} ${mod.moduleName} (v${mod.moduleVersion}, ${mod.durationMs}ms)`);
    lines.push("");

    if (mod.error) {
      lines.push(`> **Error:** ${mod.error}`);
      lines.push("");
      continue;
    }

    if (mod.checks.length > 0) {
      lines.push("| Status | Check | Details |");
      lines.push("|--------|-------|---------|");
      for (const check of mod.checks) {
        const msg = check.message ? check.message.replace(/\|/g, "\\|") : "";
        lines.push(`| ${check.status} | ${check.name} | ${msg} |`);
      }
      lines.push("");
    }
  }

  // Key findings
  const keyFindings = report.findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM"
  );
  if (keyFindings.length > 0) {
    lines.push("## Key Findings");
    lines.push("");

    for (const f of keyFindings) {
      lines.push(`### \`${f.severity}\` ${f.title}`);
      lines.push("");
      lines.push(f.description);
      lines.push("");
      if (f.cweId) lines.push(`**CWE:** ${f.cweId}`);
      if (f.toolName) lines.push(`**Tool:** ${f.toolName}`);
      lines.push(`**Remediation:** ${f.remediation}`);
      lines.push("");
    }
  }

  // Compliance
  if (report.compliance) {
    lines.push("## Compliance Mapping");
    lines.push("");
    for (const [framework, controls] of Object.entries({
      "NIST SP 800-171": report.compliance.nist,
      "SOC 2 TSC": report.compliance.soc2,
      "OWASP ASVS v4.0": report.compliance.asvs,
    })) {
      if (Object.keys(controls).length > 0) {
        lines.push(`### ${framework}`);
        lines.push("");
        for (const [id, count] of Object.entries(controls).sort(
          (a, b) => b[1] - a[1]
        )) {
          lines.push(`- **${id}** (${count} finding${count > 1 ? "s" : ""})`);
        }
        lines.push("");
      }
    }
  }

  // Footer
  lines.push("---");
  lines.push(`*Generated by [vs-mcpaudit](https://github.com/vs-mcpaudit/vs-mcpaudit) v${report.cliVersion}*`);

  console.log(lines.join("\n"));
}

// ─── HTML Output ─────────────────────────────────────────────────────────────

function outputHtml(report: ScanReport): void {
  const { server, modules, summary } = report;
  const score = summary.securityScore;
  const grade = scoreToGrade(score);
  const scoreColor = score >= 80 ? "#22c55e" : score >= 50 ? "#eab308" : "#ef4444";

  const checksHtml = modules.map((mod) => {
    const checks = mod.checks.map((c) => {
      const colors: Record<string, string> = {
        PASS: "#22c55e", WARN: "#eab308", FAIL: "#ef4444", SKIP: "#6b7280", ERROR: "#a855f7",
      };
      const bg = colors[c.status] ?? "#6b7280";
      return `<div class="check"><span class="badge" style="background:${bg}">${c.status}</span> <span class="check-name">${esc(c.name)}</span>${c.message ? `<span class="check-msg"> &mdash; ${esc(c.message)}</span>` : ""}</div>`;
    }).join("\n");
    const icon = mod.error ? "&#10007;" : "&#10003;";
    return `<div class="module"><h3>${icon} ${esc(mod.moduleName)} <span class="version">v${mod.moduleVersion} (${mod.durationMs}ms)</span></h3>${mod.error ? `<div class="error">${esc(mod.error)}</div>` : checks}</div>`;
  }).join("\n");

  const findingsHtml = report.findings
    .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM")
    .map((f) => {
      const colors: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#6b7280", INFO: "#3b82f6" };
      return `<div class="finding"><span class="badge" style="background:${colors[f.severity] ?? "#6b7280"}">${f.severity}</span> <strong>${esc(f.title)}</strong><p>${esc(f.description)}</p>${f.cweId ? `<span class="cwe">${f.cweId}</span>` : ""}${f.toolName ? ` <span class="tool">Tool: ${esc(f.toolName)}</span>` : ""}<p class="remediation">${esc(f.remediation)}</p></div>`;
    }).join("\n");

  const complianceHtml = report.compliance ? `
    <div class="compliance">
      <h2>Compliance Mapping</h2>
      ${Object.entries({ "NIST SP 800-171": report.compliance.nist, "SOC 2 TSC": report.compliance.soc2, "OWASP ASVS v4.0": report.compliance.asvs })
        .filter(([, controls]) => Object.keys(controls).length > 0)
        .map(([framework, controls]) => `<h3>${framework}</h3><div class="controls">${Object.entries(controls).sort((a, b) => b[1] - a[1]).map(([id, count]) => `<span class="control">${id} <em>(${count})</em></span>`).join(" ")}</div>`).join("\n")}
      <p class="dim">${report.compliance.mappedFindings} mapped, ${report.compliance.unmappedFindings} unmapped</p>
    </div>` : "";

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Audit Report &mdash; ${esc(server.serverInfo.name)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#030303;color:#d4d4d4;padding:2rem;max-width:960px;margin:0 auto}
h1{font-size:2rem;color:#22d3ee;margin-bottom:.5rem;font-weight:800;letter-spacing:-0.025em}
h2{font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid #262626;padding-bottom:.5rem;text-transform:uppercase;letter-spacing:0.05em;color:#737373}
h3{font-size:1rem;margin:1rem 0 .5rem;color:#a3a3a3}
.header{background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1.5rem 2rem;margin-bottom:2rem}
.meta{color:#525252;font-size:.8rem;margin-top:.5rem}
.score-card{display:flex;align-items:center;gap:2rem;background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1.5rem 2rem;margin-bottom:2rem}
.score-ring{position:relative;width:120px;height:120px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.score-ring .label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-ring .num{font-size:2rem;font-weight:700;color:${scoreColor}}
.score-ring .grade{font-size:.85rem;color:#737373}
.stats{display:flex;gap:1.5rem;flex-wrap:wrap}
.stat{text-align:center}
.stat .n{font-size:1.5rem;font-weight:700}
.stat .l{font-size:.7rem;color:#525252;text-transform:uppercase;letter-spacing:0.05em}
.module{background:#111;border:1px solid #171717;border-radius:4px;padding:1rem 1.5rem;margin-bottom:1rem}
.check{padding:4px 0;font-size:.85rem;border-bottom:1px solid #171717}
.check:last-child{border-bottom:none}
.badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:.65rem;font-weight:700;color:#fff;min-width:44px;text-align:center;text-transform:uppercase}
.check-name{font-weight:500;margin-left:8px}
.check-msg{color:#525252}
.version{font-weight:400;color:#404040;font-size:.75rem;margin-left:8px}
.finding{background:#0a0a0a;border-left:3px solid #ef4444;border-radius:2px;padding:1rem 1.5rem;margin-bottom:.75rem}
.finding p{margin:.5rem 0;font-size:.85rem;color:#a3a3a3}
.remediation{color:#22c55e;font-size:.8rem;margin-top:.5rem;background:#052e16;padding:8px;border-radius:2px}
.cwe{background:#171717;padding:2px 6px;border-radius:2px;font-size:.75rem;color:#737373}
.tool{color:#525252;font-size:.75rem}
.compliance{background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1rem 1.5rem;margin-bottom:1rem}
.controls{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
.control{background:#171717;padding:3px 8px;border-radius:2px;font-size:.75rem;color:#d4d4d4;border:1px solid #262626}
.control em{color:#525252;font-style:normal;margin-left:4px}
.dim{color:#404040;font-size:.8rem;margin-top:.75rem}
.footer{text-align:center;margin-top:3rem;padding:1.5rem;border-top:1px solid #171717;color:#404040;font-size:.8rem}
.footer a{color:#22d3ee;text-decoration:none}
</style></head><body>
<div class="header"><h1>MCP Audit Report</h1>
<div class="meta">${esc(server.serverInfo.name)} v${esc(server.serverInfo.version)} &bull; Protocol ${esc(server.protocolVersion)} &bull; ${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts &bull; ${report.durationMs}ms</div></div>
<div class="score-card"><div class="score-ring"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="#334155" stroke-width="10"/><circle cx="60" cy="60" r="52" fill="none" stroke="${scoreColor}" stroke-width="10" stroke-dasharray="${(score / 100) * 327} 327" stroke-linecap="round"/></svg><div class="label"><span class="num">${score}</span><span class="grade">Grade ${grade}</span></div></div>
<div class="stats"><div class="stat"><div class="n" style="color:#22c55e">${summary.passed}</div><div class="l">Passed</div></div><div class="stat"><div class="n" style="color:#eab308">${summary.warnings}</div><div class="l">Warnings</div></div><div class="stat"><div class="n" style="color:#ef4444">${summary.failed}</div><div class="l">Failed</div></div><div class="stat"><div class="n">${summary.totalChecks}</div><div class="l">Total</div></div></div></div>
<h2>Module Results</h2>
${checksHtml}
${findingsHtml.length > 0 ? `<h2>Key Findings</h2>${findingsHtml}` : ""}
${complianceHtml}
<div class="footer">Generated by <a href="https://github.com/vs-mcpaudit/vs-mcpaudit">vs-mcpaudit</a> v${esc(report.cliVersion)} on ${new Date(report.timestamp).toLocaleString()}</div>
</body></html>`;

  console.log(html);
}

/** Escape HTML entities */
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
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
