/**
 * Pre-commit hook installer.
 *
 * Installs a git pre-commit hook that runs vs-mcpaudit scan
 * before each commit. Fails the commit if critical findings exist.
 *
 * Usage:
 *   vs-mcpaudit hook install
 *   vs-mcpaudit hook uninstall
 */

import { writeFileSync, unlinkSync, existsSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";

const HOOK_CONTENT = `#!/bin/sh
# vs-mcpaudit pre-commit hook
# Runs MCP server security audit before each commit.
# Install: vs-mcpaudit hook install
# Remove:  vs-mcpaudit hook uninstall

echo "[vs-mcpaudit] Running pre-commit security scan..."

# Check if .mcpauditrc.json exists with server config
if [ -f ".mcpauditrc.json" ]; then
  npx vs-mcpaudit scan --ci --accept 2>/dev/null
  EXIT_CODE=$?

  if [ $EXIT_CODE -eq 3 ]; then
    echo ""
    echo "[vs-mcpaudit] CRITICAL findings detected. Commit blocked."
    echo "[vs-mcpaudit] Run 'npx vs-mcpaudit scan' for details."
    exit 1
  fi

  if [ $EXIT_CODE -eq 2 ]; then
    echo "[vs-mcpaudit] WARNING: Security findings detected (non-blocking)."
  fi
else
  echo "[vs-mcpaudit] No .mcpauditrc.json found, skipping scan."
fi

exit 0
`;

export function executeHook(action: string): void {
  const gitDir = resolve(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    console.error(chalk.red("  Error: Not a git repository"));
    process.exitCode = 1;
    return;
  }

  const hookPath = resolve(gitDir, "hooks", "pre-commit");

  switch (action) {
    case "install": {
      if (existsSync(hookPath)) {
        console.log(
          chalk.yellow("  Pre-commit hook already exists. Overwriting...")
        );
      }
      writeFileSync(hookPath, HOOK_CONTENT, "utf-8");
      chmodSync(hookPath, 0o755);
      console.log(chalk.green("  Pre-commit hook installed successfully."));
      console.log(
        chalk.dim("  The hook will run vs-mcpaudit scan before each commit.")
      );
      break;
    }
    case "uninstall": {
      if (!existsSync(hookPath)) {
        console.log(chalk.dim("  No pre-commit hook found."));
        return;
      }
      unlinkSync(hookPath);
      console.log(chalk.green("  Pre-commit hook removed."));
      break;
    }
    default:
      console.error(
        chalk.red(`  Unknown action: ${action}. Use "install" or "uninstall".`)
      );
      process.exitCode = 1;
  }
}
