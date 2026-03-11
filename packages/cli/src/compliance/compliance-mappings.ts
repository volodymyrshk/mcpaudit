/**
 * Compliance framework mappings from CWE IDs.
 * Maps security findings to regulatory and industry framework controls.
 */

export interface ComplianceMapping {
  cweId: string;
  owasp: string[];      // OWASP Top 10 2021 categories
  nist: string[];        // NIST 800-53 Rev 5 controls
  atlas: string[];       // MITRE ATLAS techniques
}

export const COMPLIANCE_MAPPINGS: ComplianceMapping[] = [
  {
    cweId: "CWE-78",
    owasp: ["A03:2021 Injection"],
    nist: ["SI-10", "SI-3"],
    atlas: ["AML.T0040"],
  },
  {
    cweId: "CWE-89",
    owasp: ["A03:2021 Injection"],
    nist: ["SI-10", "SI-3"],
    atlas: ["AML.T0040"],
  },
  {
    cweId: "CWE-94",
    owasp: ["A03:2021 Injection"],
    nist: ["SI-10", "SI-3", "SI-7"],
    atlas: ["AML.T0043"],
  },
  {
    cweId: "CWE-918",
    owasp: ["A10:2021 Server-Side Request Forgery"],
    nist: ["SC-7", "SI-10"],
    atlas: ["AML.T0040"],
  },
  {
    cweId: "CWE-22",
    owasp: ["A01:2021 Broken Access Control"],
    nist: ["AC-3", "SI-10"],
    atlas: [],
  },
  {
    cweId: "CWE-79",
    owasp: ["A03:2021 Injection"],
    nist: ["SI-10", "SI-3"],
    atlas: [],
  },
  {
    cweId: "CWE-200",
    owasp: ["A01:2021 Broken Access Control"],
    nist: ["AC-3", "SC-28", "SI-11"],
    atlas: ["AML.T0024", "AML.T0044"],
  },
  {
    cweId: "CWE-201",
    owasp: ["A01:2021 Broken Access Control"],
    nist: ["AC-3", "SC-28"],
    atlas: ["AML.T0024"],
  },
  {
    cweId: "CWE-250",
    owasp: ["A04:2021 Insecure Design"],
    nist: ["AC-6", "CM-7"],
    atlas: [],
  },
  {
    cweId: "CWE-269",
    owasp: ["A04:2021 Insecure Design"],
    nist: ["AC-6"],
    atlas: ["AML.T0048.002"],
  },
  {
    cweId: "CWE-345",
    owasp: ["A08:2021 Software and Data Integrity Failures"],
    nist: ["SI-7", "SC-8"],
    atlas: ["AML.T0043"],
  },
  {
    cweId: "CWE-400",
    owasp: ["A04:2021 Insecure Design"],
    nist: ["SC-5", "SI-10"],
    atlas: ["AML.T0029"],
  },
  {
    cweId: "CWE-441",
    owasp: ["A08:2021 Software and Data Integrity Failures"],
    nist: ["SC-7", "SI-10"],
    atlas: ["AML.T0043"],
  },
  {
    cweId: "CWE-494",
    owasp: ["A08:2021 Software and Data Integrity Failures"],
    nist: ["SI-7", "CM-11"],
    atlas: ["AML.T0010"],
  },
  {
    cweId: "CWE-522",
    owasp: ["A07:2021 Identification and Authentication Failures"],
    nist: ["IA-5", "SC-28"],
    atlas: ["AML.T0024"],
  },
  {
    cweId: "CWE-732",
    owasp: ["A01:2021 Broken Access Control"],
    nist: ["AC-3", "AC-6"],
    atlas: [],
  },
  {
    cweId: "CWE-757",
    owasp: ["A02:2021 Cryptographic Failures"],
    nist: ["SC-12", "SC-13"],
    atlas: [],
  },
  {
    cweId: "CWE-862",
    owasp: ["A01:2021 Broken Access Control"],
    nist: ["AC-3", "AC-6"],
    atlas: ["AML.T0048"],
  },
  {
    cweId: "CWE-1059",
    owasp: ["A04:2021 Insecure Design"],
    nist: ["SA-11", "SA-15"],
    atlas: [],
  },
  {
    cweId: "CWE-1188",
    owasp: ["A05:2021 Security Misconfiguration"],
    nist: ["CM-6", "CM-7"],
    atlas: ["AML.T0043"],
  },
  {
    cweId: "CWE-20",
    owasp: ["A03:2021 Injection"],
    nist: ["SI-10", "SI-3"],
    atlas: ["AML.T0040", "AML.T0043"],
  },
];
