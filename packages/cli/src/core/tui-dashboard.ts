import chalk from "chalk";
import type { AuditModule, ModuleResult, CheckResult, CheckStatus, ReportSummary } from "../types/index.js";
import { scoreToGrade, scoreToColor } from "./scorer.js";

/**
 * Interactive TUI Dashboard — live module progress, findings stream,
 * and animated score reveal. Enterprise-grade visual output.
 */

// ─── Box drawing characters ─────────────────────────────────────────────────

const BOX = {
  tl: "╭", tr: "╮", bl: "╰", br: "╯",
  h: "─", v: "│",
  lt: "├", rt: "┤", mt: "┬", mb: "┴",
};

const WIDTH = 78;

function hLine(left: string, right: string, fill = BOX.h): string {
  return left + fill.repeat(WIDTH - 2) + right;
}

function padRow(content: string, rawLen: number): string {
  const padding = WIDTH - 2 - rawLen;
  return `${BOX.v} ${content}${" ".repeat(Math.max(0, padding - 1))}${BOX.v}`;
}

// ─── Live Progress Renderer ─────────────────────────────────────────────────

interface ModuleStatus {
  id: string;
  name: string;
  mode: string;
  status: "pending" | "running" | "done" | "error";
  durationMs?: number;
  checkCount?: number;
  findingCount?: number;
  detailMessage?: string;
}

export class TuiDashboard {
  private modules: ModuleStatus[] = [];
  private startTime = 0;
  private liveFindings: Array<{ severity: string; title: string; tool?: string }> = [];
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private rendered = false;

  /**
   * Initialize dashboard with module list.
   */
  init(modules: AuditModule[]): void {
    this.startTime = performance.now();
    this.modules = modules.map((m) => ({
      id: m.id,
      name: m.name,
      mode: m.mode,
      status: "pending",
    }));
    this.liveFindings = [];
    this.rendered = false;

    // Render initial state
    this.render();

    // Start live refresh
    this.intervalId = setInterval(() => this.render(), 250);
  }

  /**
   * Mark a module as started.
   */
  onModuleStart(moduleId: string): void {
    const mod = this.modules.find((m) => m.id === moduleId);
    if (mod) {
      mod.status = "running";
      mod.detailMessage = undefined;
    }
  }

  /**
   * Update the detail message for the currently running module.
   */
  onDetailProgress(message: string): void {
    const running = this.modules.find((m) => m.status === "running");
    if (running) {
      running.detailMessage = message;
    }
  }

  /**
   * Mark a module as complete with results.
   */
  onModuleComplete(moduleId: string, result: ModuleResult): void {
    const mod = this.modules.find((m) => m.id === moduleId);
    if (mod) {
      mod.status = result.error ? "error" : "done";
      mod.durationMs = result.durationMs;
      mod.checkCount = result.checks.length;
      mod.findingCount = result.findings.length;
      mod.detailMessage = undefined;

      // Stream findings to live feed
      for (const f of result.findings) {
        this.liveFindings.push({
          severity: f.severity,
          title: f.title.substring(0, 60),
          tool: f.toolName,
        });
      }
    }
  }

  /**
   * Finalize dashboard and show final score.
   */
  finalize(summary: ReportSummary): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.render();
    this.renderScoreReveal(summary);
  }

  /**
   * Stop the dashboard (cleanup).
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  // ─── Rendering ──────────────────────────────────────────────────────────

  private render(): void {
    const elapsed = Math.round((performance.now() - this.startTime) / 1000);
    const done = this.modules.filter((m) => m.status === "done" || m.status === "error").length;
    const total = this.modules.length;
    const running = this.modules.find((m) => m.status === "running");

    // Clear previous render
    if (this.rendered) {
      const lineCount = this.getRenderedLineCount();
      process.stderr.write(`\x1b[${lineCount}A\x1b[J`);
    }

    const lines: string[] = [];

    // Header
    lines.push(chalk.dim(hLine(BOX.tl, BOX.tr)));
    const headerText = `  SCANNING  ${done}/${total} modules  ${elapsed}s elapsed`;
    lines.push(chalk.dim(padRow(chalk.bold.cyan(headerText), headerText.length)));
    lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));

    // Progress bar
    const barWidth = WIDTH - 8;
    const progress = total > 0 ? done / total : 0;
    const filled = Math.round(progress * barWidth);
    const empty = barWidth - filled;
    const barStr = chalk.cyan("█".repeat(filled)) + chalk.dim("░".repeat(empty));
    const pctStr = `${Math.round(progress * 100)}%`;
    lines.push(chalk.dim(padRow(`${barStr} ${chalk.bold(pctStr)}`, barWidth + pctStr.length + 1)));
    lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));

    // Module list
    for (const mod of this.modules) {
      const icon = this.statusIcon(mod.status);
      const timing = mod.durationMs !== undefined ? chalk.dim(` ${mod.durationMs}ms`) : "";
      const counts = mod.checkCount !== undefined
        ? chalk.dim(` [${mod.checkCount} checks, ${mod.findingCount} findings]`)
        : "";
      const detail = mod.detailMessage
        ? chalk.dim(` → ${mod.detailMessage.substring(0, 40)}`)
        : "";
      const badge = mod.mode === "active" ? chalk.red(" ⚡") : "";

      const line = `${icon} ${mod.name}${badge}${timing}${counts}${detail}`;
      const rawLen = this.stripAnsi(line).length;
      lines.push(chalk.dim(BOX.v) + ` ${line}${" ".repeat(Math.max(0, WIDTH - rawLen - 3))}` + chalk.dim(BOX.v));
    }

    // Live findings feed (last 5)
    if (this.liveFindings.length > 0) {
      lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));
      const feedTitle = " LIVE FINDINGS ";
      const feedPad = Math.floor((WIDTH - 2 - feedTitle.length) / 2);
      lines.push(chalk.dim(BOX.v) + chalk.dim("─".repeat(feedPad)) + chalk.bold.yellow(feedTitle) + chalk.dim("─".repeat(WIDTH - 2 - feedPad - feedTitle.length)) + chalk.dim(BOX.v));

      const recent = this.liveFindings.slice(-5);
      for (const f of recent) {
        const sevColor = f.severity === "CRITICAL" ? chalk.bgRed.white
          : f.severity === "HIGH" ? chalk.red
          : f.severity === "MEDIUM" ? chalk.yellow
          : chalk.dim;
        const sev = sevColor(` ${f.severity.padEnd(8)} `);
        const tool = f.tool ? chalk.dim(` [${f.tool}]`) : "";
        const text = `${sev} ${f.title}${tool}`;
        const rawLen2 = this.stripAnsi(text).length;
        lines.push(chalk.dim(BOX.v) + ` ${text}${" ".repeat(Math.max(0, WIDTH - rawLen2 - 3))}` + chalk.dim(BOX.v));
      }

      if (this.liveFindings.length > 5) {
        const moreMsg = chalk.dim(`  ... and ${this.liveFindings.length - 5} more`);
        const rawLen3 = this.stripAnsi(moreMsg).length;
        lines.push(chalk.dim(BOX.v) + ` ${moreMsg}${" ".repeat(Math.max(0, WIDTH - rawLen3 - 3))}` + chalk.dim(BOX.v));
      }
    }

    // Footer
    lines.push(chalk.dim(hLine(BOX.bl, BOX.br)));

    process.stderr.write(lines.join("\n") + "\n");
    this.rendered = true;
  }

  private renderScoreReveal(summary: ReportSummary): void {
    const score = summary.securityScore;
    const grade = scoreToGrade(score);
    const color = scoreToColor(score);
    const colorFn = color === "green" ? chalk.green : color === "yellow" ? chalk.yellow : chalk.red;

    console.log();
    console.log(chalk.dim(hLine(BOX.tl, BOX.tr)));

    // Big score display
    const scoreStr = `  SECURITY SCORE: ${score}/100  GRADE: ${grade}  `;
    const scorePad = Math.floor((WIDTH - 2 - scoreStr.length) / 2);
    console.log(
      chalk.dim(BOX.v) +
      " ".repeat(scorePad) +
      colorFn.bold(scoreStr) +
      " ".repeat(Math.max(0, WIDTH - 2 - scorePad - scoreStr.length)) +
      chalk.dim(BOX.v)
    );

    // Score bar
    const barWidth = WIDTH - 8;
    const filled = Math.round((score / 100) * barWidth);
    const empty = barWidth - filled;
    const bar = colorFn("█".repeat(filled)) + chalk.dim("░".repeat(empty));
    console.log(chalk.dim(BOX.v) + `  ${bar}  ` + chalk.dim(BOX.v));

    // Severity breakdown
    const s = summary.findingsBySeverity;
    const parts = [
      chalk.red(`CRIT:${s.CRITICAL}`),
      chalk.red(`HIGH:${s.HIGH}`),
      chalk.yellow(`MED:${s.MEDIUM}`),
      chalk.dim(`LOW:${s.LOW}`),
      chalk.green(`PASS:${summary.passed}`),
      chalk.yellow(`WARN:${summary.warnings}`),
      chalk.red(`FAIL:${summary.failed}`),
    ];
    const breakdownStr = parts.join("  ");
    const rawLen = this.stripAnsi(breakdownStr).length;
    const breakdownPad = Math.floor((WIDTH - 2 - rawLen) / 2);
    console.log(
      chalk.dim(BOX.v) +
      " ".repeat(breakdownPad) +
      breakdownStr +
      " ".repeat(Math.max(0, WIDTH - 2 - breakdownPad - rawLen)) +
      chalk.dim(BOX.v)
    );

    console.log(chalk.dim(hLine(BOX.bl, BOX.br)));
    console.log();
  }

  private getRenderedLineCount(): number {
    // Header(3) + progress(2) + modules + findings + footer
    let count = 3 + 2 + this.modules.length + 1;
    if (this.liveFindings.length > 0) {
      count += 2 + Math.min(this.liveFindings.length, 5);
      if (this.liveFindings.length > 5) count++;
    }
    return count;
  }

  private statusIcon(status: ModuleStatus["status"]): string {
    switch (status) {
      case "pending": return chalk.dim("○");
      case "running": return chalk.cyan("◉");
      case "done": return chalk.green("●");
      case "error": return chalk.red("✗");
    }
  }

  private stripAnsi(s: string): string {
    return s.replace(/\x1b\[[0-9;]*m/g, "");
  }
}
