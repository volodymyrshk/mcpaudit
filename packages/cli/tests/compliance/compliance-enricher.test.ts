import { describe, test, expect } from "bun:test";
import { enrichFindings, generateComplianceSummary } from "../../src/compliance/compliance-enricher.js";
import { Severity } from "../../src/types/index.js";
import type { Finding } from "../../src/types/index.js";

describe("Compliance Enricher", () => {
  const baseFinding: Finding = {
    id: "TEST-001",
    module: "test",
    severity: Severity.HIGH,
    title: "Test finding",
    description: "Test",
    evidence: {},
    remediation: "Fix it",
  };

  test("enriches finding with known CWE mapping", () => {
    const findings = [{ ...baseFinding, cweId: "CWE-918" }];
    const enriched = enrichFindings(findings);

    expect(enriched[0].compliance).toBeDefined();
    expect(enriched[0].compliance!.owasp).toContain("A10:2021 Server-Side Request Forgery");
    expect(enriched[0].compliance!.nist).toContain("SC-7");
  });

  test("leaves finding without CWE unmapped", () => {
    const findings = [baseFinding];
    const enriched = enrichFindings(findings);

    expect(enriched[0].compliance).toBeUndefined();
  });

  test("leaves finding with unknown CWE unmapped", () => {
    const findings = [{ ...baseFinding, cweId: "CWE-99999" }];
    const enriched = enrichFindings(findings);

    expect(enriched[0].compliance).toBeUndefined();
  });

  test("generates correct compliance summary", () => {
    const findings = [
      { ...baseFinding, cweId: "CWE-918" },
      { ...baseFinding, id: "TEST-002", cweId: "CWE-78" },
      { ...baseFinding, id: "TEST-003" }, // no CWE
    ];

    const enriched = enrichFindings(findings);
    const summary = generateComplianceSummary(enriched);

    expect(summary.mappedFindings).toBe(2);
    expect(summary.unmappedFindings).toBe(1);
    expect(summary.owasp["A03:2021 Injection"]).toBe(1);
    expect(summary.owasp["A10:2021 Server-Side Request Forgery"]).toBe(1);
    expect(summary.nist["SI-10"]).toBe(2); // Both CWE-918 and CWE-78 map to SI-10
  });

  test("handles empty findings list", () => {
    const enriched = enrichFindings([]);
    const summary = generateComplianceSummary(enriched);

    expect(summary.mappedFindings).toBe(0);
    expect(summary.unmappedFindings).toBe(0);
    expect(Object.keys(summary.owasp)).toHaveLength(0);
  });
});
