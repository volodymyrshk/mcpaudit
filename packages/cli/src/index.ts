#!/usr/bin/env node

import { Command } from "commander";
import { executeScan } from "./commands/scan.js";
import { ensureAcceptance, forceAcceptance } from "./core/acceptance.js";

const CLI_VERSION = "0.1.0-alpha.1";

const program = new Command();

program
  .name("vs-mcpaudit")
  .description(
    "Security audit tool for MCP (Model Context Protocol) servers.\n" +
      "The only tool that actively stress-tests running MCP servers for vulnerabilities."
  )
  .version(CLI_VERSION);

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
    "Output format (terminal or json)",
    "terminal"
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
    "--compliance <frameworks...>",
    "Enable compliance mapping (nist, soc2, asvs, or all)"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .action(async (opts) => {
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
    if (opts.ci) {
      opts.format = "json";
      opts.verbose = false;
    }

    await executeScan({
      server: opts.server,
      transport: opts.transport as "stdio" | "streamable-http",
      format: opts.format as "terminal" | "json",
      active: opts.active,
      modules: opts.modules,
      verbose: opts.verbose,
      timeout: parseInt(opts.timeout, 10),
      output: opts.output,
      compliance: opts.compliance,
      probeTimeout: parseInt(opts.probeTimeout, 10),
      probeDelay: parseInt(opts.probeDelay, 10),
    });
  });

// ─── list-modules command ──────────────────────────────────────────────────────
program
  .command("list-modules")
  .description("List all available audit modules")
  .action(() => {
    console.log();
    console.log("  Available Audit Modules:");
    console.log("  ─".repeat(25));
    console.log();
    console.log("  tool-permissions      Analyzes tool schemas for over-permissioning        [passive]");
    console.log("  transport-security    Checks transport config, capabilities, supply chain  [passive]");
    console.log("  schema-manipulation   Detects prompt injection in tool descriptions        [passive]");
    console.log("  context-extraction    Detects data exfiltration chains and context leaks   [passive]");
    console.log("  ssrf-detection        Probes URL tools for SSRF vulnerabilities            [active]");
    console.log("  active-fuzzer         Fuzzes tool parameters with adversarial payloads         [active]");
    console.log();
    console.log("  Active modules require --active flag to enable.");
    console.log();
  });

// ─── Parse and execute ─────────────────────────────────────────────────────────
program.parse();
