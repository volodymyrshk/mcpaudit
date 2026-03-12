import type { ComplianceControl } from "../types/index.js";

/**
 * Compliance framework mappings from CWE IDs.
 *
 * Maps security findings to three regulatory/industry frameworks:
 *   - NIST SP 800-171 (CMMC Level 2 alignment)
 *   - SOC 2 Trust Services Criteria (TSC)
 *   - OWASP ASVS v4.0 (Application Security Verification Standard)
 */

export const CWE_COMPLIANCE_MAP: Record<string, ComplianceControl[]> = {
  "CWE-78": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.8",
      controlTitle: "Output Encoding",
      requirement: "Verify that OS command injection defenses are in place",
    },
  ],
  "CWE-89": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.4",
      controlTitle: "Output Encoding",
      requirement: "Verify use of parameterized queries to prevent SQL injection",
    },
  ],
  "CWE-94": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.2.4",
      controlTitle: "Sanitization and Sandboxing",
      requirement: "Verify that code injection defenses are in place for server-side templates and dynamic code execution",
    },
  ],
  "CWE-74": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.2.1",
      controlTitle: "Sanitization and Sandboxing",
      requirement: "Verify that all untrusted input is sanitized using a safe allow-list approach",
    },
  ],
  "CWE-918": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.6",
      controlTitle: "Network Communication by Exception",
      requirement: "Deny network communications traffic by default and allow by exception",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.6",
      controlTitle: "System Boundary Protections",
      requirement: "Restrict access to system boundaries and implement controls against threats",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V12.6.1",
      controlTitle: "SSRF Protection",
      requirement: "Verify that the web or application server is configured with an allowlist of resources to which the server can send requests or load data",
    },
  ],
  "CWE-22": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.2",
      controlTitle: "Transaction & Function Control",
      requirement: "Limit system access to the types of transactions and functions that authorized users are permitted to execute",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V12.3.1",
      controlTitle: "File Execution",
      requirement: "Verify that user-submitted filenames are validated to prevent path traversal",
    },
  ],
  "CWE-79": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.3",
      controlTitle: "Output Encoding",
      requirement: "Verify that context-aware output escaping is used to protect against reflected, stored, and DOM XSS",
    },
  ],
  "CWE-200": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.3",
      controlTitle: "CUI Flow Control",
      requirement: "Control the flow of CUI in accordance with approved authorizations",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.5",
      controlTitle: "Disposal of Information",
      requirement: "Restrict unauthorized access to confidential information during disposal",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V7.4.1",
      controlTitle: "Error Handling",
      requirement: "Verify that a generic message is shown when an unexpected or security-sensitive error occurs",
    },
  ],
  "CWE-201": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.3",
      controlTitle: "CUI Flow Control",
      requirement: "Control the flow of CUI in accordance with approved authorizations",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.5",
      controlTitle: "Disposal of Information",
      requirement: "Restrict unauthorized access to confidential information during disposal",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V7.4.1",
      controlTitle: "Error Handling",
      requirement: "Verify that a generic message is shown when an unexpected or security-sensitive error occurs",
    },
  ],
  "CWE-250": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.5",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, including for specific security functions and privileged accounts",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.4.3",
      controlTitle: "Access Control Architecture",
      requirement: "Verify that the application uses a single and well-vetted access control mechanism",
    },
  ],
  "CWE-269": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.5",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, including for specific security functions and privileged accounts",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.4.3",
      controlTitle: "Access Control Architecture",
      requirement: "Verify that the application uses a single and well-vetted access control mechanism",
    },
  ],
  "CWE-345": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.14.2",
      controlTitle: "Malicious Code Protection",
      requirement: "Provide protection from malicious code at designated locations within organizational systems",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC7.1",
      controlTitle: "Detection and Monitoring",
      requirement: "Detect and monitor for anomalies that indicate risks to the achievement of objectives",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V10.3.2",
      controlTitle: "Deployed Integrity Controls",
      requirement: "Verify that the application employs integrity protections such as code signing or subresource integrity",
    },
  ],
  "CWE-400": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.6",
      controlTitle: "System Boundary Protections",
      requirement: "Restrict access to system boundaries and implement controls against threats",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V11.1.4",
      controlTitle: "Business Logic Security",
      requirement: "Verify that the application has anti-automation controls to protect against excessive calls",
    },
  ],
  "CWE-710": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.4.2",
      controlTitle: "Security Configuration Enforcement",
      requirement: "Establish and enforce security configuration settings for IT products",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC8.1",
      controlTitle: "Change Management",
      requirement: "Authorize, design, develop, configure, document, test, and implement changes",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.1.7",
      controlTitle: "Secure SDLC",
      requirement: "Verify availability of secure coding checklist, security requirements, or guidelines",
    },
  ],
  "CWE-732": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.2",
      controlTitle: "Transaction & Function Control",
      requirement: "Limit system access to the types of transactions and functions that authorized users are permitted to execute",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V4.1.3",
      controlTitle: "General Access Control",
      requirement: "Verify that the principle of least privilege exists — users should only be able to access functions for which they possess specific authorization",
    },
  ],
  "CWE-912": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.14.2",
      controlTitle: "Malicious Code Protection",
      requirement: "Provide protection from malicious code at designated locations within organizational systems",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC7.1",
      controlTitle: "Detection and Monitoring",
      requirement: "Detect and monitor for anomalies that indicate risks to the achievement of objectives",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V10.2.1",
      controlTitle: "Malicious Code Search",
      requirement: "Verify that the application does not contain hidden functionality or backdoors",
    },
  ],
  "CWE-20": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.1.3",
      controlTitle: "Input Validation",
      requirement: "Verify that all input is validated, including length, range, format, and business rules",
    },
  ],
  "CWE-522": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.5.10",
      controlTitle: "Cryptographically-Protected Passwords",
      requirement: "Store and transmit only cryptographically-protected passwords",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V2.4.1",
      controlTitle: "Credential Storage",
      requirement: "Verify that passwords are stored in a form resistant to offline attacks",
    },
  ],
  "CWE-757": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.11",
      controlTitle: "FIPS-Validated Cryptography",
      requirement: "Employ FIPS-validated cryptography when used to protect CUI",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V6.2.1",
      controlTitle: "Algorithms",
      requirement: "Verify that all cryptographic modules fail securely and use industry-proven algorithms",
    },
  ],
  "CWE-862": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.1",
      controlTitle: "Authorized Access Control",
      requirement: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V4.1.1",
      controlTitle: "General Access Control",
      requirement: "Verify that the application enforces access control rules on a trusted service layer",
    },
  ],
  "CWE-1188": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.4.2",
      controlTitle: "Security Configuration Enforcement",
      requirement: "Establish and enforce security configuration settings for IT products",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC8.1",
      controlTitle: "Change Management",
      requirement: "Authorize, design, develop, configure, document, test, and implement changes",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V14.2.1",
      controlTitle: "Dependency",
      requirement: "Verify that all components are up to date with proper security configuration",
    },
  ],
};
