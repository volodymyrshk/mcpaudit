/**
 * Severity levels for security findings, ordered by impact.
 */
export enum Severity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO",
}

/**
 * A compliance framework control mapped to a finding.
 */
export interface ComplianceControl {
  /** Framework name (e.g., "NIST SP 800-171", "SOC 2 TSC", "OWASP ASVS") */
  framework: string;
  /** Control identifier (e.g., "3.1.1", "CC6.1", "V5.1") */
  controlId: string;
  /** Human-readable control title */
  controlTitle: string;
  /** Requirement description */
  requirement: string;
}

/**
 * A single security finding discovered during an audit.
 */
export interface Finding {
  /** Unique identifier for this finding (e.g., "TP-001") */
  id: string;
  /** Module that discovered this finding */
  module: string;
  /** Severity level */
  severity: Severity;
  /** Short title describing the finding */
  title: string;
  /** Detailed description of the vulnerability */
  description: string;
  /** Evidence that triggered this finding (tool name, schema excerpt, response data) */
  evidence: Record<string, unknown>;
  /** Remediation guidance */
  remediation: string;
  /** MCP tool name involved, if applicable */
  toolName?: string;
  /** CWE ID if mappable */
  cweId?: string;
  /** Compliance controls this finding maps to */
  complianceControls?: ComplianceControl[];
}

/**
 * Result status for an individual security check within a module.
 */
export enum CheckStatus {
  PASS = "PASS",
  WARN = "WARN",
  FAIL = "FAIL",
  SKIP = "SKIP",
  ERROR = "ERROR",
}

/**
 * A single check result (more granular than a Finding).
 */
export interface CheckResult {
  /** Check identifier */
  id: string;
  /** Human-readable check name */
  name: string;
  /** Result status */
  status: CheckStatus;
  /** Optional message with details */
  message?: string;
  /** Associated finding if status is WARN or FAIL */
  finding?: Finding;
}
