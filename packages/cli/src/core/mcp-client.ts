import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  ServerCapabilities,
  ToolInfo,
  ResourceInfo,
  PromptInfo,
} from "../types/index.js";

const CLI_VERSION = "0.1.0-alpha.1";
const PROTOCOL_VERSION = "2025-11-05";

export interface ConnectOptions {
  /** Server command to spawn (e.g., "npx") */
  command: string;
  /** Arguments for the command (e.g., ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]) */
  args: string[];
  /** Environment variables to pass to the server process */
  env?: Record<string, string>;
  /** Connection timeout in milliseconds */
  timeoutMs?: number;
  /** Verbose logging */
  verbose?: boolean;
}

/**
 * MCP Client Engine.
 * Connects to MCP servers via stdio transport, performs the initialization
 * handshake, and enumerates all server capabilities (tools, resources, prompts).
 */
export class MCPClientEngine {
  private client: Client | null = null;
  private transport: StdioClientTransport | null = null;
  private verbose: boolean = false;

  /**
   * Connect to an MCP server, perform initialization handshake,
   * and return the full server capabilities manifest.
   */
  async connect(options: ConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    const timeoutMs = options.timeoutMs ?? 30_000;

    this.log(`Connecting to MCP server: ${options.command} ${options.args.join(" ")}`);

    // Create stdio transport — spawns the server process
    this.transport = new StdioClientTransport({
      command: options.command,
      args: options.args,
      env: options.env ? { ...process.env, ...options.env } : undefined,
    });

    // Create MCP client
    this.client = new Client(
      {
        name: "vs-mcpaudit",
        version: CLI_VERSION,
      },
      {
        capabilities: {},
      }
    );

    // Connect with timeout
    const connectPromise = this.client.connect(this.transport);
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs)
    );

    await Promise.race([connectPromise, timeoutPromise]);
    this.log("MCP handshake completed successfully");

    // Enumerate all capabilities
    const capabilities = await this.enumerate();
    return capabilities;
  }

  /**
   * Enumerate all server capabilities: tools, resources, and prompts.
   * Handles cursor-based pagination per MCP spec.
   */
  private async enumerate(): Promise<ServerCapabilities> {
    if (!this.client) throw new Error("Not connected");

    const serverInfo = this.client.getServerVersion() ?? {
      name: "unknown",
      version: "unknown",
    };
    const serverCapabilities = this.client.getServerCapabilities() ?? {};

    this.log(`Server: ${serverInfo.name} v${serverInfo.version}`);

    // Enumerate tools with pagination
    const tools = await this.enumerateTools();
    this.log(`Discovered ${tools.length} tools`);

    // Enumerate resources with pagination
    const resources = await this.enumerateResources();
    this.log(`Discovered ${resources.length} resources`);

    // Enumerate prompts with pagination
    const prompts = await this.enumeratePrompts();
    this.log(`Discovered ${prompts.length} prompts`);

    return {
      serverInfo: {
        name: serverInfo.name ?? "unknown",
        version: serverInfo.version ?? "unknown",
      },
      protocolVersion:
        (serverInfo as Record<string, unknown>).protocolVersion as string ??
        PROTOCOL_VERSION,
      capabilities: serverCapabilities,
      tools,
      resources,
      prompts,
    };
  }

  /**
   * Enumerate all tools, handling cursor-based pagination.
   */
  private async enumerateTools(): Promise<ToolInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allTools: ToolInfo[] = [];
    let cursor: string | undefined;

    try {
      do {
        const result = await this.client.listTools(
          cursor ? { cursor } : undefined
        );
        for (const tool of result.tools) {
          allTools.push({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema as Record<string, unknown>,
            annotations: tool.annotations as ToolInfo["annotations"],
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Tool enumeration failed (server may not support tools): ${err}`);
    }

    return allTools;
  }

  /**
   * Enumerate all resources, handling cursor-based pagination.
   */
  private async enumerateResources(): Promise<ResourceInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allResources: ResourceInfo[] = [];
    let cursor: string | undefined;

    try {
      do {
        const result = await this.client.listResources(
          cursor ? { cursor } : undefined
        );
        for (const resource of result.resources) {
          allResources.push({
            uri: resource.uri,
            name: resource.name,
            description: resource.description,
            mimeType: resource.mimeType,
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Resource enumeration failed: ${err}`);
    }

    return allResources;
  }

  /**
   * Enumerate all prompts, handling cursor-based pagination.
   */
  private async enumeratePrompts(): Promise<PromptInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allPrompts: PromptInfo[] = [];
    let cursor: string | undefined;

    try {
      do {
        const result = await this.client.listPrompts(
          cursor ? { cursor } : undefined
        );
        for (const prompt of result.prompts) {
          allPrompts.push({
            name: prompt.name,
            description: prompt.description,
            arguments: prompt.arguments?.map((a) => ({
              name: a.name,
              description: a.description,
              required: a.required,
            })),
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Prompt enumeration failed: ${err}`);
    }

    return allPrompts;
  }

  /**
   * Call a tool on the connected MCP server.
   * Used by active audit modules (e.g., SSRF probes).
   */
  async callTool(
    name: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    if (!this.client) throw new Error("Not connected");
    this.log(`Calling tool: ${name} with args: ${JSON.stringify(args)}`);

    const result = await this.client.callTool({
      name,
      arguments: args,
    });

    return result;
  }

  /**
   * Gracefully disconnect from the MCP server.
   */
  async disconnect(): Promise<void> {
    this.log("Disconnecting from MCP server");
    try {
      await this.client?.close();
    } catch {
      // Ignore disconnect errors
    }
    this.client = null;
    this.transport = null;
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[vs-mcpaudit:mcp] ${message}`);
    }
  }
}
