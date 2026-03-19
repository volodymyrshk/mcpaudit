#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { executeScan } from "./commands/scan.js";
import { executeScanSource } from "./commands/scan-source.js";
import { executeAuditLocal } from "./commands/audit-local.js";
import { executeBadge } from "./commands/badge.js";
import { executeDiff } from "./commands/diff.js";
import { executeHook } from "./commands/hook.js";
import { ensureAcceptance, forceAcceptance } from "./core/acceptance.js";
import { printBanner } from "./core/reporter.js";
import { loadConfig, loadCustomPayloads, loadIgnoreList } from "./core/config.js";
import { resolveProfile, isProfileName, type ProfileDefaults } from "./core/profiles.js";

const CLI_VERSION = "0.1.0-alpha.1";

const program = new Command();

program
  .name("vs-mcpaudit")
  .description(
    "Security audit tool for MCP (Model Context Protocol) servers.\n" +
      "The only tool that actively stress-tests running MCP servers for vulnerabilities."
  )
  .version(CLI_VERSION)
  .addHelpText("beforeAll", () => {
    // Show banner on --help
    printBanner(`v${CLI_VERSION}`);
    return "";
  });

// ─── scan command ──────────────────────────────────────────────────────────────
program
  .command("scan")
  .description("Scan an MCP server for security vulnerabilities")
  .requiredOption(
    "-s, --server <command>",
    'MCP server command to scan (e.g., "npx -y @modelcontextprotocol/server-filesystem /tmp")'
  )
  .option(
    "-t, --transport <type>",
    "Transport type (stdio or streamable-http)",
    "stdio"
  )
  .option(
    "-f, --format <format>",
    "Output format (terminal, json, html, or markdown)",
    "terminal"
  )
  .option(
    "-p, --profile <name>",
    "Scan profile: quick (passive only), standard (passive+active), enterprise (full suite)"
  )
  .option(
    "--active",
    "Enable active scanning modules (makes tool calls to the server)",
    false
  )
  .option(
    "-m, --modules <modules...>",
    "Run specific modules only (space-separated module IDs)"
  )
  .option("-v, --verbose", "Enable verbose output", false)
  .option(
    "--timeout <ms>",
    "Connection timeout in milliseconds",
    "30000"
  )
  .option(
    "--ci",
    "CI mode: no color, no progress, JSON output, non-zero exit on findings",
    false
  )
  .option(
    "-o, --output <file>",
    "Save report to file (use .sarif extension for SARIF format)"
  )
  .option(
    "--probe-timeout <ms>",
    "Timeout per active probe in milliseconds",
    "5000"
  )
  .option(
    "--probe-delay <ms>",
    "Delay between active probes in milliseconds",
    "100"
  )
  .option(
    "--min-severity <level>",
    "Only show findings at or above this level (CRITICAL, HIGH, MEDIUM, LOW)"
  )
  .option(
    "--compliance <frameworks...>",
    "Enable compliance mapping (nist, soc2, asvs, or all)"
  )
  .option(
    "--payloads <file>",
    "Load custom fuzzing payloads from a JSON file"
  )
  .option(
    "--config <file>",
    "Path to config file (default: .mcpauditrc.json)"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .option(
    "--tui",
    "Enable interactive TUI dashboard with live progress",
    false
  )
  .option(
    "--autofix",
    "Show auto-fix suggestions with code patches for findings",
    false
  )
  .option(
    "--executive-summary",
    "Include executive summary for non-technical stakeholders",
    false
  )
  .option(
    "--rules <file>",
    "Load custom policy rules from a YAML/JSON file"
  )
  .option(
    "--fail-below <score>",
    "Exit non-zero if security score is below this threshold (0-100)"
  )
  .action(async (opts) => {
    // Load config file
    const config = loadConfig(opts.config);

    // ── Resolve profile defaults ────────────────────────────────────────
    const profileName = opts.profile ?? config.profile;
    let profileDefaults: ProfileDefaults | null = null;
    if (profileName) {
      if (!isProfileName(profileName)) {
        console.error(
          chalk.red(`  Unknown profile "${profileName}". Available: quick, standard, enterprise`)
        );
        process.exit(1);
      }
      profileDefaults = resolveProfile(profileName);
    }

    // ── Smart defaults: auto-enable features in interactive terminals ───
    const isInteractive = process.stdout.isTTY && !opts.ci && !process.env.CI;
    const userPassedFlag = (flag: string) => process.argv.includes(flag);

    // ── Merge: profile < config < CLI flags (most specific wins) ────────
    const format = opts.format !== "terminal" ? opts.format : (config.format ?? "terminal");
    const active = opts.active || config.active || profileDefaults?.active || false;
    const compliance = opts.compliance ?? config.compliance ?? profileDefaults?.compliance;
    const minSeverity = (opts.minSeverity ?? config.minSeverity ?? profileDefaults?.minSeverity)?.toUpperCase();
    const modules = opts.modules ?? config.modules;
    const verbose = opts.verbose || config.verbose || profileDefaults?.verbose || false;
    const timeout = opts.timeout !== "30000" ? parseInt(opts.timeout, 10) : (config.timeout ?? 30000);
    const probeTimeout = opts.probeTimeout !== "5000" ? parseInt(opts.probeTimeout, 10) : (config.probeTimeout ?? 5000);
    const probeDelay = opts.probeDelay !== "100" ? parseInt(opts.probeDelay, 10) : (config.probeDelay ?? 100);

    // Smart defaults: TUI, autofix, executive-summary auto-enable in TTY
    // unless user explicitly passed --no-tui style (not possible with Commander boolean, so just check argv)
    const tui = userPassedFlag("--tui")
      ? opts.tui
      : (profileDefaults?.tui ?? (isInteractive ? true : false));
    const autofix = userPassedFlag("--autofix")
      ? opts.autofix
      : (profileDefaults?.autofix ?? (isInteractive ? true : false));
    const executiveSummary = userPassedFlag("--executive-summary")
      ? opts.executiveSummary
      : (profileDefaults?.executiveSummary ?? (isInteractive ? true : false));

    // Load custom payloads
    const payloadsFile = opts.payloads ?? config.payloads;
    const customPayloads = payloadsFile ? loadCustomPayloads(payloadsFile) : undefined;

    // Load ignore list
    const ignoreList = loadIgnoreList(config.ignore);

    // Handle acceptance
    if (opts.accept || opts.ci) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    // CI mode overrides
    const finalFormat = opts.ci ? "json" : format;
    const finalVerbose = opts.ci ? false : verbose;

    await executeScan({
      server: opts.server,
      transport: opts.transport as "stdio" | "streamable-http",
      format: finalFormat as "terminal" | "json" | "html" | "markdown",
      active,
      modules,
      verbose: finalVerbose,
      timeout,
      output: opts.output,
      compliance,
      probeTimeout,
      probeDelay,
      minSeverity,
      customPayloads,
      ignoreList: ignoreList.size > 0 ? ignoreList : undefined,
      tui: tui && !opts.ci,
      autofix,
      executiveSummary,
      rules: opts.rules,
      failBelow: opts.failBelow ? parseInt(opts.failBelow, 10) : undefined,
    });
  });

// ─── scan-all command ────────────────────────────────────────────────────────
program
  .command("scan-all")
  .description("Scan multiple MCP servers defined in a registry file")
  .requiredOption(
    "-r, --registry <file>",
    "Path to registry JSON file defining servers to scan"
  )
  .option(
    "-f, --format <format>",
    "Output format for individual reports (terminal, json, html, markdown)",
    "terminal"
  )
  .option("--active", "Enable active scanning for all servers", false)
  .option(
    "-p, --profile <name>",
    "Default scan profile for all servers (quick, standard, enterprise)"
  )
  .option("-o, --output-dir <dir>", "Save individual reports to directory")
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .action(async (opts) => {
    if (opts.accept) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    const { executeScanAll } = await import("./commands/scan-all.js");
    await executeScanAll({
      registry: opts.registry,
      format: opts.format,
      active: opts.active,
      outputDir: opts.outputDir,
      profile: opts.profile,
      accept: opts.accept,
    });
  });

// ─── audit-local command ─────────────────────────────────────────────────────
program
  .command("audit-local")
  .description("Discover and scan all MCP servers from local IDE configs")
  .option(
    "--active",
    "Enable active scanning modules (makes tool calls to servers)",
    false
  )
  .option(
    "--compliance <frameworks...>",
    "Enable compliance mapping (nist, soc2, asvs, or all)"
  )
  .option(
    "-o, --output <dir>",
    "Save individual reports to directory"
  )
  .option(
    "--timeout <ms>",
    "Connection timeout per server in milliseconds",
    "30000"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .action(async (opts) => {
    // Handle acceptance
    if (opts.accept) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    await executeAuditLocal({
      active: opts.active,
      compliance: opts.compliance,
      outputDir: opts.output,
      timeout: parseInt(opts.timeout, 10),
    });
  });

// ─── scan-source command ────────────────────────────────────────────────────────
program
  .command("scan-source")
  .description("Static analysis of MCP server source code (pre-deployment security)")
  .argument("<path>", "Directory or file to scan")
  .option(
    "-f, --format <format>",
    "Output format (terminal or json)",
    "terminal"
  )
  .option(
    "--min-severity <level>",
    "Only show findings at or above this level (CRITICAL, HIGH, MEDIUM, LOW)"
  )
  .action(async (path, opts) => {
    await executeScanSource({
      path,
      format: opts.format as "terminal" | "json",
      minSeverity: opts.minSeverity,
    });
  });

// ─── badge command ──────────────────────────────────────────────────────────────
program
  .command("badge")
  .description("Generate an SVG score badge for READMEs and dashboards")
  .option("--score <number>", "Security score (0-100)")
  .option("-i, --input <file>", "Read score from a JSON report file")
  .option("-o, --output <file>", "Save SVG to file (default: stdout)")
  .option("--label <text>", "Badge label", "MCP Audit")
  .action((opts) => {
    executeBadge({
      score: opts.score !== undefined ? parseInt(opts.score, 10) : undefined,
      input: opts.input,
      output: opts.output,
      label: opts.label,
    });
  });

// ─── diff command ───────────────────────────────────────────────────────────────
program
  .command("diff <baseline> <current>")
  .description("Compare two scan reports and show new/fixed findings")
  .action((baseline, current) => {
    executeDiff(baseline, current);
  });

// ─── list-modules command ──────────────────────────────────────────────────────
program
  .command("list-modules")
  .description("List all available audit modules")
  .action(() => {
    printBanner("Available Audit Modules");

    const modules = [
      { id: "tool-permissions",        desc: "Analyzes tool schemas for over-permissioning",       mode: "passive" },
      { id: "transport-security",      desc: "Checks transport config, capabilities, supply chain", mode: "passive" },
      { id: "schema-manipulation",     desc: "Detects prompt injection in tool descriptions",       mode: "passive" },
      { id: "context-extraction",      desc: "Detects data exfiltration chains and context leaks",  mode: "passive" },
      { id: "secret-leak-detection",   desc: "Scans schemas for leaked API keys, tokens, secrets",  mode: "passive" },
      { id: "resource-prompt-audit",   desc: "Audits resources and prompts for access/injection",   mode: "passive" },
      { id: "supply-chain-analysis",   desc: "Analyzes server metadata for supply-chain risks",     mode: "passive" },
      { id: "ssrf-detection",          desc: "Probes URL tools for SSRF vulnerabilities",           mode: "active"  },
      { id: "active-fuzzer",           desc: "Fuzzes tool params with adversarial + mutated payloads", mode: "active"  },
      { id: "tool-shadowing",         desc: "Detects tools lying about schema or behavior",         mode: "active"  },
      { id: "response-fingerprinting", desc: "Detects non-deterministic responses and hidden state", mode: "active"  },
      { id: "auth-boundary-testing",   desc: "Probes authorization scoping and access boundaries",  mode: "active"  },
    ];

    console.log();
    console.log(chalk.bold("  Scan Profiles:"));
    console.log(chalk.dim("    quick       ") + "Passive checks only, fast (~5s)");
    console.log(chalk.dim("    standard    ") + "Passive + active probes (~30s)");
    console.log(chalk.dim("    enterprise  ") + "Full suite with compliance, TUI, autofix, summary (~60s)");
    console.log();
    console.log(chalk.bold("  Modules:"));

    for (const m of modules) {
      const id = chalk.bold(m.id.padEnd(24));
      const desc = m.desc;
      const badge = m.mode === "active"
        ? chalk.red(`[${m.mode}]`)
        : chalk.green(`[${m.mode}]`);
      console.log(`    ${id} ${desc}  ${badge}`);
    }

    console.log();
    console.log(chalk.dim("  Active modules require ") + chalk.bold("--active") + chalk.dim(" or ") + chalk.bold("--profile standard/enterprise") + chalk.dim(" to enable."));
    console.log();
  });

// ─── hook command ──────────────────────────────────────────────────────────────
program
  .command("hook <action>")
  .description("Manage git pre-commit hook (install or uninstall)")
  .action((action) => {
    executeHook(action);
  });

// ─── init command ──────────────────────────────────────────────────────────────
program
  .command("init")
  .description("Create a .mcpauditrc.json config file in the current directory")
  .action(async () => {
    const { writeFileSync, existsSync } = await import("node:fs");
    const path = ".mcpauditrc.json";
    if (existsSync(path)) {
      console.log(chalk.yellow(`  ${path} already exists`));
      return;
    }

    const template = {
      profile: "standard",
      format: "terminal",
      active: false,
      compliance: [],
      modules: [],
      ignore: [],
      timeout: 30000,
      probeTimeout: 5000,
      probeDelay: 100,
    };

    writeFileSync(path, JSON.stringify(template, null, 2) + "\n", "utf-8");
    console.log(chalk.green(`  Created ${path}`));
  });

// ─── Default action: wizard when no command is given ─────────────────────────
program.action(async () => {
  // Only launch wizard in interactive terminals
  if (!process.stdin.isTTY) {
    program.help();
    return;
  }

  const { runWizard } = await import("./core/wizard.js");
  const result = await runWizard();

  if (!result.confirmed || !result.server) {
    return;
  }

  // Handle acceptance
  const accepted = await ensureAcceptance();
  if (!accepted) {
    process.exit(1);
  }

  // Resolve profile
  const profileDefaults = resolveProfile(result.profile);

  await executeScan({
    server: result.server,
    transport: "stdio",
    format: result.format,
    active: profileDefaults.active,
    verbose: profileDefaults.verbose,
    timeout: 30000,
    output: result.output,
    compliance: profileDefaults.compliance,
    tui: profileDefaults.tui,
    autofix: profileDefaults.autofix,
    executiveSummary: profileDefaults.executiveSummary,
    minSeverity: profileDefaults.minSeverity,
  });
});

// ─── Parse and execute ─────────────────────────────────────────────────────────
program.parse();
