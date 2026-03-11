import type { Finding } from "../types/index.js";
import { COMPLIANCE_MAPPINGS, type ComplianceMapping } from "./compliance-mappings.js";

/**
 * Enriched finding with compliance framework references.
 */
export interface ComplianceFinding extends Finding {
  compliance?: {
    owasp: string[];
    nist: string[];
    atlas: string[];
  };
}

/**
 * Summary of compliance framework coverage from a scan.
 */
export interface ComplianceSummary {
  /** OWASP Top 10 2021 categories hit */
  owasp: Record<string, number>;
  /** NIST 800-53 controls hit */
  nist: Record<string, number>;
  /** MITRE ATLAS techniques hit */
  atlas: Record<string, number>;
  /** Total findings with compliance mappings */
  mappedFindings: number;
  /** Total findings without compliance mappings */
  unmappedFindings: number;
}

// Build lookup map for fast access
const CWE_TO_COMPLIANCE = new Map<string, ComplianceMapping>();
for (const mapping of COMPLIANCE_MAPPINGS) {
  CWE_TO_COMPLIANCE.set(mapping.cweId, mapping);
}

/**
 * Enrich a list of findings with compliance framework references.
 */
export function enrichFindings(findings: Finding[]): ComplianceFinding[] {
  return findings.map((finding) => {
    if (!finding.cweId) return finding as ComplianceFinding;

    const mapping = CWE_TO_COMPLIANCE.get(finding.cweId);
    if (!mapping) return finding as ComplianceFinding;

    return {
      ...finding,
      compliance: {
        owasp: mapping.owasp,
        nist: mapping.nist,
        atlas: mapping.atlas,
      },
    };
  });
}

/**
 * Generate a compliance summary from enriched findings.
 */
export function generateComplianceSummary(findings: ComplianceFinding[]): ComplianceSummary {
  const owasp: Record<string, number> = {};
  const nist: Record<string, number> = {};
  const atlas: Record<string, number> = {};
  let mappedFindings = 0;
  let unmappedFindings = 0;

  for (const finding of findings) {
    if (finding.compliance) {
      mappedFindings++;
      for (const cat of finding.compliance.owasp) {
        owasp[cat] = (owasp[cat] ?? 0) + 1;
      }
      for (const ctrl of finding.compliance.nist) {
        nist[ctrl] = (nist[ctrl] ?? 0) + 1;
      }
      for (const tech of finding.compliance.atlas) {
        atlas[tech] = (atlas[tech] ?? 0) + 1;
      }
    } else {
      unmappedFindings++;
    }
  }

  return { owasp, nist, atlas, mappedFindings, unmappedFindings };
}

// TODO: add support for SOC2 and HIPAA mappings once we have the data
