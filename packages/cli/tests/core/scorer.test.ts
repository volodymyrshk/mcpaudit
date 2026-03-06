import { describe, test, expect } from "bun:test";
import { calculateScore, scoreToGrade, scoreToColor } from "../../src/core/scorer.js";
import { Severity, CheckStatus } from "../../src/types/index.js";
import type { ModuleResult, Finding } from "../../src/types/index.js";

function makeFinding(severity: Severity, id: string = "TEST-001"): Finding {
  return {
    id,
    module: "test-module",
    severity,
    title: `Test finding ${id}`,
    description: "Test finding description",
    evidence: {},
    remediation: "Fix it",
  };
}

function makeModuleResult(findings: Finding[]): ModuleResult {
  return {
    moduleId: "test-module",
    moduleName: "Test Module",
    moduleVersion: "1.0.0",
    durationMs: 10,
    checks: findings.map((f) => ({
      id: f.id,
      name: f.title,
      status: CheckStatus.FAIL,
      finding: f,
    })),
    findings,
  };
}

describe("Scorer", () => {
  describe("calculateScore", () => {
    test("perfect score with no findings", () => {
      const result = makeModuleResult([]);
      result.checks = [
        { id: "C1", name: "Check 1", status: CheckStatus.PASS },
        { id: "C2", name: "Check 2", status: CheckStatus.PASS },
      ];
      result.findings = [];

      const summary = calculateScore([result]);
      expect(summary.securityScore).toBe(100);
      expect(summary.passed).toBe(2);
      expect(summary.failed).toBe(0);
    });

    test("single CRITICAL finding drops score significantly", () => {
      const result = makeModuleResult([
        makeFinding(Severity.CRITICAL, "CRIT-1"),
      ]);

      const summary = calculateScore([result]);
      expect(summary.securityScore).toBe(75); // 100 - 25
      expect(summary.findingsBySeverity[Severity.CRITICAL]).toBe(1);
    });

    test("single HIGH finding moderate impact", () => {
      const result = makeModuleResult([
        makeFinding(Severity.HIGH, "HIGH-1"),
      ]);

      const summary = calculateScore([result]);
      expect(summary.securityScore).toBe(85); // 100 - 15
    });

    test("diminishing returns on multiple same-severity findings", () => {
      // 5 MEDIUM findings should not = 5 * 5 = 25
      // With diminishing factor 0.6: 5 + 3 + 1.8 + 1.08 + 0.65 ≈ 11.5
      const findings = Array.from({ length: 5 }, (_, i) =>
        makeFinding(Severity.MEDIUM, `MED-${i}`)
      );
      const result = makeModuleResult(findings);

      const summary = calculateScore([result]);
      // Score should be ~88-89, not 75 (which is what linear would give)
      expect(summary.securityScore).toBeGreaterThan(85);
      expect(summary.securityScore).toBeLessThan(95);
    });

    test("per-module impact is capped at 40", () => {
      // 20 CRITICAL findings would be 20 * 25 = 500 without cap
      const findings = Array.from({ length: 20 }, (_, i) =>
        makeFinding(Severity.CRITICAL, `CRIT-${i}`)
      );
      const result = makeModuleResult(findings);

      const summary = calculateScore([result]);
      expect(summary.securityScore).toBe(60); // 100 - 40 (capped)
    });

    test("multiple modules accumulate deductions", () => {
      const mod1 = makeModuleResult([makeFinding(Severity.HIGH, "H1")]);
      mod1.moduleId = "mod1";
      const mod2 = makeModuleResult([makeFinding(Severity.HIGH, "H2")]);
      mod2.moduleId = "mod2";

      const summary = calculateScore([mod1, mod2]);
      expect(summary.securityScore).toBe(70); // 100 - 15 - 15
    });

    test("LOW findings have minimal impact", () => {
      const findings = Array.from({ length: 10 }, (_, i) =>
        makeFinding(Severity.LOW, `LOW-${i}`)
      );
      const result = makeModuleResult(findings);

      const summary = calculateScore([result]);
      // LOW weight = 2, with diminishing returns ~5 total deduction
      expect(summary.securityScore).toBeGreaterThan(90);
    });

    test("INFO findings have zero impact", () => {
      const findings = Array.from({ length: 20 }, (_, i) =>
        makeFinding(Severity.INFO, `INFO-${i}`)
      );
      const result = makeModuleResult(findings);

      const summary = calculateScore([result]);
      expect(summary.securityScore).toBe(100);
    });

    test("correctly counts check statuses", () => {
      const result: ModuleResult = {
        moduleId: "test",
        moduleName: "Test",
        moduleVersion: "1.0.0",
        durationMs: 10,
        checks: [
          { id: "C1", name: "Pass", status: CheckStatus.PASS },
          { id: "C2", name: "Pass", status: CheckStatus.PASS },
          { id: "C3", name: "Warn", status: CheckStatus.WARN },
          { id: "C4", name: "Fail", status: CheckStatus.FAIL },
          { id: "C5", name: "Skip", status: CheckStatus.SKIP },
        ],
        findings: [],
      };

      const summary = calculateScore([result]);
      expect(summary.totalChecks).toBe(5);
      expect(summary.passed).toBe(2);
      expect(summary.warnings).toBe(1);
      expect(summary.failed).toBe(1);
      expect(summary.skipped).toBe(1);
    });

    test("filesystem server calibration: many MEDIUM + LOW → 60+", () => {
      // Simulates the official filesystem server results:
      // ~12 MEDIUM findings from tool-permissions, 1 MEDIUM from transport,
      // 4 LOW from schema-manipulation, 2 MEDIUM + 1 LOW from context-extraction
      const mod1 = makeModuleResult(
        Array.from({ length: 12 }, (_, i) =>
          makeFinding(Severity.MEDIUM, `TP-${i}`)
        )
      );
      mod1.moduleId = "tool-permissions";

      const mod2 = makeModuleResult([
        makeFinding(Severity.MEDIUM, "TS-1"),
      ]);
      mod2.moduleId = "transport-security";

      const mod3 = makeModuleResult(
        Array.from({ length: 4 }, (_, i) =>
          makeFinding(Severity.LOW, `SM-${i}`)
        )
      );
      mod3.moduleId = "schema-manipulation";

      const mod4 = makeModuleResult([
        makeFinding(Severity.MEDIUM, "CE-1"),
        makeFinding(Severity.MEDIUM, "CE-2"),
      ]);
      mod4.moduleId = "context-extraction";

      const summary = calculateScore([mod1, mod2, mod3, mod4]);
      // Should be 60+ (not 30 like before)
      expect(summary.securityScore).toBeGreaterThanOrEqual(60);
    });
  });

  describe("scoreToGrade", () => {
    test("A for 90+", () => expect(scoreToGrade(95)).toBe("A"));
    test("B for 80-89", () => expect(scoreToGrade(85)).toBe("B"));
    test("C for 70-79", () => expect(scoreToGrade(75)).toBe("C"));
    test("D for 60-69", () => expect(scoreToGrade(65)).toBe("D"));
    test("F for <60", () => expect(scoreToGrade(50)).toBe("F"));
  });

  describe("scoreToColor", () => {
    test("green for 80+", () => expect(scoreToColor(85)).toBe("green"));
    test("yellow for 50-79", () => expect(scoreToColor(65)).toBe("yellow"));
    test("red for <50", () => expect(scoreToColor(30)).toBe("red"));
  });
});
