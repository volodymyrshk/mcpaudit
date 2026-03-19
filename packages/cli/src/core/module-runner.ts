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
  /** Timeout per active probe in ms */
  probeTimeout?: number;
  /** Delay between active probes in ms */
  probeDelay?: number;
  /** Progress callback for module lifecycle (result is passed on complete/error) */
  onProgress?: (moduleId: string, status: "start" | "complete" | "error", result?: ModuleResult) => void;
  /** Granular progress callback for active module status updates */
  onDetailProgress?: (message: string) => void;
  /** Custom payloads for active fuzzing */
  customPayloads?: Array<{ value: string; label: string }>;
}

/**
 * Module Runner — orchestrates the execution of audit modules.
 * Runs passive modules in parallel, active modules sequentially.
 */
export class ModuleRunner {
  /**
   * Execute all audit modules and aggregate results.
   * Passive modules run concurrently for speed.
   * Active modules run sequentially (they make tool calls that may conflict).
   */
  async run(options: RunnerOptions): Promise<ModuleResult[]> {
    const {
      capabilities,
      modules,
      callTool,
      activeMode = false,
      verbose = false,
      probeTimeout,
      probeDelay,
      onProgress,
      onDetailProgress,
      customPayloads,
    } = options;

    // Split into passive and active modules
    const passiveModules = modules.filter((m) => m.mode === "passive");
    const activeModules = modules.filter((m) => m.mode === "active");

    const context: ModuleContext = {
      capabilities,
      callTool,
      activeMode,
      verbose,
      probeTimeout,
      probeDelay,
      onProgress: onDetailProgress,
      customPayloads,
    };

    // ── Run passive modules in parallel ──────────────────────────────────
    const passiveResults = await Promise.all(
      passiveModules.map((mod) => this.runModule(mod, context, onProgress, verbose))
    );
    // Notify completion for all passive modules (they started in parallel)
    for (const result of passiveResults) {
      onProgress?.(result.moduleId, result.error ? "error" : "complete", result);
    }

    // ── Run active modules sequentially ──────────────────────────────────
    const activeResults: ModuleResult[] = [];
    for (const mod of activeModules) {
      if (!activeMode) {
        if (verbose) {
          console.error(
            `[vs-mcpaudit:runner] Skipping active module "${mod.id}" (use --active to enable)`
          );
        }
        continue;
      }

      onProgress?.(mod.id, "start");
      const result = await this.runModule(mod, context, undefined, verbose);
      onProgress?.(mod.id, result.error ? "error" : "complete", result);
      activeResults.push(result);
    }

    return [...passiveResults, ...activeResults];
  }

  /**
   * Run a single module with error isolation.
   */
  private async runModule(
    mod: AuditModule,
    context: ModuleContext,
    onProgress?: (moduleId: string, status: "start" | "complete" | "error", result?: ModuleResult) => void,
    verbose: boolean = false
  ): Promise<ModuleResult> {
    onProgress?.(mod.id, "start");
    const startTime = performance.now();

    try {
      const checks = await mod.run(context);
      const durationMs = Math.round(performance.now() - startTime);

      // Extract findings from check results
      const findings: Finding[] = checks
        .filter((c): c is CheckResult & { finding: Finding } => !!c.finding)
        .map((c) => c.finding);

      return {
        moduleId: mod.id,
        moduleName: mod.name,
        moduleVersion: mod.version,
        durationMs,
        checks,
        findings,
      };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMessage =
        err instanceof Error ? err.message : String(err);

      if (verbose) {
        console.error(
          `[vs-mcpaudit:runner] Module "${mod.id}" crashed: ${errorMessage}`
        );
      }

      return {
        moduleId: mod.id,
        moduleName: mod.name,
        moduleVersion: mod.version,
        durationMs,
        checks: [],
        findings: [],
        error: errorMessage,
      };
    }
  }
}
