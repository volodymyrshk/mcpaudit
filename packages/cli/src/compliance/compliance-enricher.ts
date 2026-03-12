import type { Finding, ComplianceControl } from "../types/index.js";
import { CWE_COMPLIANCE_MAP } from "../data/compliance-mappings.js";

/**
 * Summary of compliance framework coverage from a scan.
 */
export interface ComplianceSummary {
  /** NIST SP 800-171 controls hit */
  nist: Record<string, number>;
  /** SOC 2 TSC controls hit */
  soc2: Record<string, number>;
  /** OWASP ASVS controls hit */
  asvs: Record<string, number>;
  /** Total findings with compliance mappings */
  mappedFindings: number;
  /** Total findings without compliance mappings */
  unmappedFindings: number;
}

/**
 * Enrich a list of findings with compliance framework references.
 * Attaches `complianceControls` directly to each Finding.
 */
export function enrichFindings(findings: Finding[]): Finding[] {
  return findings.map((finding) => {
    if (!finding.cweId) return finding;

    const controls = CWE_COMPLIANCE_MAP[finding.cweId];
    if (!controls || controls.length === 0) return finding;

    return {
      ...finding,
      complianceControls: controls,
    };
  });
}

/**
 * Generate a compliance summary from enriched findings.
 */
export function generateComplianceSummary(findings: Finding[]): ComplianceSummary {
  const nist: Record<string, number> = {};
  const soc2: Record<string, number> = {};
  const asvs: Record<string, number> = {};
  let mappedFindings = 0;
  let unmappedFindings = 0;

  for (const finding of findings) {
    if (finding.complianceControls && finding.complianceControls.length > 0) {
      mappedFindings++;
      for (const control of finding.complianceControls) {
        switch (control.framework) {
          case "NIST SP 800-171":
            nist[control.controlId] = (nist[control.controlId] ?? 0) + 1;
            break;
          case "SOC 2 TSC":
            soc2[control.controlId] = (soc2[control.controlId] ?? 0) + 1;
            break;
          case "OWASP ASVS":
            asvs[control.controlId] = (asvs[control.controlId] ?? 0) + 1;
            break;
        }
      }
    } else {
      unmappedFindings++;
    }
  }

  return { nist, soc2, asvs, mappedFindings, unmappedFindings };
}
