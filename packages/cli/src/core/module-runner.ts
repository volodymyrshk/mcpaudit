import type {
  AuditModule,
  ModuleContext,
  ModuleResult,
  ServerCapabilities,
  Finding,
  CheckResult,
} from "../types/index.js";

export interface RunnerOptions {
  /** Server capabilities manifest */
  capabilities: ServerCapabilities;
  /** Modules to execute */
  modules: AuditModule[];
  /** Function to call MCP tools (for active modules) */
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  /** Enable active scanning modules */
  activeMode?: boolean;
  /** Verbose logging */
  verbose?: boolean;
  /** Progress callback */
  onProgress?: (moduleId: string, status: "start" | "complete" | "error") => void;
}

/**
 * Module Runner — orchestrates the execution of audit modules.
 * Runs modules sequentially, isolates failures, and aggregates results.
 */
export class ModuleRunner {
  /**
   * Execute all audit modules and aggregate results.
   */
  async run(options: RunnerOptions): Promise<ModuleResult[]> {
    const {
      capabilities,
      modules,
      callTool,
      activeMode = false,
      verbose = false,
      onProgress,
    } = options;

    const results: ModuleResult[] = [];

    for (const mod of modules) {
      // Skip active modules if active mode is not enabled
      if (mod.mode === "active" && !activeMode) {
        if (verbose) {
          console.error(
            `[agentaudit:runner] Skipping active module "${mod.id}" (use --active to enable)`
          );
        }
        continue;
      }

      onProgress?.(mod.id, "start");
      const startTime = performance.now();

      try {
        const context: ModuleContext = {
          capabilities,
          callTool,
          activeMode,
          verbose,
        };

        const checks = await mod.run(context);
        const durationMs = Math.round(performance.now() - startTime);

        // Extract findings from check results
        const findings: Finding[] = checks
          .filter((c): c is CheckResult & { finding: Finding } => !!c.finding)
          .map((c) => c.finding);

        results.push({
          moduleId: mod.id,
          moduleName: mod.name,
          moduleVersion: mod.version,
          durationMs,
          checks,
          findings,
        });

        onProgress?.(mod.id, "complete");
      } catch (err) {
        const durationMs = Math.round(performance.now() - startTime);
        const errorMessage =
          err instanceof Error ? err.message : String(err);

        if (verbose) {
          console.error(
            `[agentaudit:runner] Module "${mod.id}" crashed: ${errorMessage}`
          );
        }

        results.push({
          moduleId: mod.id,
          moduleName: mod.name,
          moduleVersion: mod.version,
          durationMs,
          checks: [],
          findings: [],
          error: errorMessage,
        });

        onProgress?.(mod.id, "error");
      }
    }

    return results;
  }
}
