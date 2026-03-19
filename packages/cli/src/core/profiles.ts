/**
 * Scan Profiles — named presets that bundle common flag combinations.
 *
 * Simplifies the CLI from 18 flags to a single --profile choice.
 * Profile defaults can be overridden by config file and CLI flags.
 */

export type ProfileName = "quick" | "standard" | "enterprise";

export interface ProfileDefaults {
  active: boolean;
  tui: boolean;
  autofix: boolean;
  executiveSummary: boolean;
  compliance?: string[];
  minSeverity?: string;
  verbose: boolean;
}

/**
 * Built-in scan profiles.
 *
 * quick      — passive checks only, fast feedback
 * standard   — passive + active probes for thorough testing
 * enterprise — full suite with compliance, TUI, autofix, exec summary
 */
export const PROFILES: Record<ProfileName, ProfileDefaults> = {
  quick: {
    active: false,
    tui: false,
    autofix: false,
    executiveSummary: false,
    verbose: false,
  },
  standard: {
    active: true,
    tui: false,
    autofix: false,
    executiveSummary: false,
    verbose: false,
  },
  enterprise: {
    active: true,
    tui: true,
    autofix: true,
    executiveSummary: true,
    compliance: ["all"],
    minSeverity: "LOW",
    verbose: false,
  },
};

/**
 * Type guard for profile names.
 */
export function isProfileName(s: string): s is ProfileName {
  return s === "quick" || s === "standard" || s === "enterprise";
}

/**
 * Resolve a profile name to its defaults.
 * Throws if the name is not a valid profile.
 */
export function resolveProfile(profileName: string): ProfileDefaults {
  if (!isProfileName(profileName)) {
    throw new Error(
      `Unknown profile "${profileName}". Available: quick, standard, enterprise`
    );
  }
  return { ...PROFILES[profileName] };
}
