import {
  Severity,
  CheckStatus,
  type ModuleResult,
  type ReportSummary,
} from "../types/index.js";

/**
 * Severity weights for score calculation.
 * Score starts at 100 and decreases per finding.
 *
 * Calibration notes (v0.1.0):
 * - CRITICAL: Direct exploit path (e.g., cloud metadata SSRF, command injection)
 * - HIGH:     Exploitable with effort (contradictory annotations, prompt injection)
 * - MEDIUM:   Risk indicator, not directly exploitable (unconstrained params, dynamic tools)
 * - LOW:      Informational risk, best-practice violation
 * - INFO:     No impact on score
 *
 * A well-maintained server with no CRITICAL/HIGH issues should score 70+.
 */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 25,
  [Severity.HIGH]: 15,
  [Severity.MEDIUM]: 5,
  [Severity.LOW]: 2,
  [Severity.INFO]: 0,
};

/**
 * Diminishing returns factor for repeated findings of the same severity
 * within a single module. The Nth finding of the same severity contributes
 * weight * (DIMINISHING_FACTOR ^ (N-1)).
 *
 * This prevents a module with 12 MEDIUM findings from dominating the score.
 * Example with MEDIUM (weight=5): 5 + 3 + 1.8 + 1.1 + ... ≈ 13 total
 * vs. linear: 5 * 12 = 60
 */
const DIMINISHING_FACTOR = 0.6;

/**
 * Maximum score impact from any single module.
 */
const MAX_MODULE_IMPACT = 40;

/**
 * Calculate security score and report summary from module results.
 */
export function calculateScore(moduleResults: ModuleResult[]): ReportSummary {
  let totalChecks = 0;
  let passed = 0;
  let warnings = 0;
  let failed = 0;
  let skipped = 0;
  let errors = 0;

  const findingsBySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  // Aggregate check statuses
  for (const result of moduleResults) {
    for (const check of result.checks) {
      totalChecks++;
      switch (check.status) {
        case CheckStatus.PASS:
          passed++;
          break;
        case CheckStatus.WARN:
          warnings++;
          break;
        case CheckStatus.FAIL:
          failed++;
          break;
        case CheckStatus.SKIP:
          skipped++;
          break;
        case CheckStatus.ERROR:
          errors++;
          break;
      }
    }

    // Count findings by severity
    for (const finding of result.findings) {
      findingsBySeverity[finding.severity]++;
    }
  }

  // Calculate security score
  const securityScore = calculateSecurityScore(moduleResults);

  return {
    totalChecks,
    passed,
    warnings,
    failed,
    skipped,
    errors,
    findingsBySeverity,
    securityScore,
  };
}

/**
 * Calculate the 0-100 security score with diminishing returns.
 *
 * For each module:
 *   1. Group findings by severity
 *   2. Apply diminishing returns within each severity group
 *   3. Cap total module impact at MAX_MODULE_IMPACT
 *   4. Deduct from 100
 *
 * This ensures:
 * - A single CRITICAL finding significantly impacts the score
 * - Repeated similar findings don't compound unfairly
 * - A well-maintained server with only LOW/MEDIUM findings scores 70+
 */
function calculateSecurityScore(moduleResults: ModuleResult[]): number {
  let score = 100;

  for (const result of moduleResults) {
    // Group findings by severity within this module
    const severityCounts = new Map<Severity, number>();
    for (const finding of result.findings) {
      severityCounts.set(
        finding.severity,
        (severityCounts.get(finding.severity) ?? 0) + 1
      );
    }

    // Calculate impact with diminishing returns per severity
    let moduleImpact = 0;
    for (const [severity, count] of severityCounts) {
      const baseWeight = SEVERITY_WEIGHTS[severity];
      for (let i = 0; i < count; i++) {
        moduleImpact += baseWeight * Math.pow(DIMINISHING_FACTOR, i);
      }
    }

    // Cap per-module impact
    score -= Math.min(moduleImpact, MAX_MODULE_IMPACT);
  }

  // Floor at 0, round to integer
  return Math.max(0, Math.round(score));
}

/**
 * Get a human-readable grade from a security score.
 */
export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Get the color associated with a score.
 */
export function scoreToColor(score: number): "green" | "yellow" | "red" {
  if (score >= 80) return "green";
  if (score >= 50) return "yellow";
  return "red";
}
