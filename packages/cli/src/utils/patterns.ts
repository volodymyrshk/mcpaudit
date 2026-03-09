/**
 * Shared regex patterns used across multiple audit modules.
 */

// URL/URI related parameters often vulnerable to SSRF
export const URL_PARAM_PATTERNS = /^(url|uri|endpoint|href|link|src|webhook|callback|redirect|target|destination|fetch_url|request_url)$/i;

// Parameters that often take raw input, susceptible to injection
export const INJECTION_PARAM_PATTERNS = /^(query|sql|statement|expression|command|cmd|exec|shell|script|code)$/i;
