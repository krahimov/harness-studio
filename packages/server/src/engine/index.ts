/**
 * Agent execution engine.
 *
 * Manages the agent loop: receives user messages, calls the LLM provider,
 * processes tool calls, and emits events. Supports streaming.
 */

import { getDB, newId } from "../db/index.js";
import type {
  LLMProvider,
  ChatMessage,
  ContentPart,
  ToolDefinition,
  ChatCompletionChunk,
} from "../providers/index.js";
import {
  loadConnectorToken,
  listMCPTools,
  callMCPTool,
  MCPClientError,
} from "../lib/mcp-client.js";
import type { Sandbox, SandboxFactory } from "../sandbox/index.js";
import { truncateOutput } from "../sandbox/index.js";

/** POSIX shell single-quote escape — safe for paths with spaces, quotes, etc. */
function shellEscape(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

export interface AgentConfig {
  name: string;
  system: string | null;
  model: string;
  tools: any[];
  mcp_servers: any[];
  skills: any[];
}

export interface SessionEventEmitter {
  emit(event: SessionEventData): void;
  close(): void;
}

export interface SessionEventData {
  id: string;
  type: string;
  [key: string]: unknown;
  processed_at: string;
}

// Built-in tool definitions for the agent toolset
const AGENT_TOOLS: ToolDefinition[] = [
  {
    name: "bash",
    description:
      "Execute a bash command in a sandboxed Linux environment. Use this to run scripts, inspect files, install packages, or test code. Returns combined stdout/stderr and exit code.",
    input_schema: {
      type: "object",
      properties: {
        command: { type: "string", description: "The bash command to execute." },
        timeout_seconds: {
          type: "number",
          description: "Maximum seconds to wait. Default 60.",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "read_file",
    description:
      "Read the contents of a file in the sandbox filesystem. Returns the full file contents (truncated if very large).",
    input_schema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the file. Absolute, or relative to the sandbox working directory.",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description:
      "Write content to a file in the sandbox, overwriting if it exists. Creates parent directories if needed.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Destination path." },
        content: { type: "string", description: "Full file content to write." },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "edit_file",
    description:
      "Replace text in a file. By default old_string must appear exactly once; pass replace_all=true to substitute every occurrence. Use to make targeted edits without rewriting the whole file.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to edit." },
        old_string: {
          type: "string",
          description: "Exact text to find. Whitespace-sensitive.",
        },
        new_string: { type: "string", description: "Replacement text." },
        replace_all: {
          type: "boolean",
          description: "Replace every occurrence. Defaults to false.",
        },
      },
      required: ["path", "old_string", "new_string"],
    },
  },
  {
    name: "web_search",
    description: "Search the web for information. Returns search results with titles, URLs, and snippets.",
    input_schema: {
      type: "object",
      properties: {
        query: { type: "string", description: "The search query" },
      },
      required: ["query"],
    },
  },
  {
    name: "web_fetch",
    description: "Fetch the content of a web page by URL.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to fetch" },
      },
      required: ["url"],
    },
  },
];

/**
 * A routing table built alongside the tool list: maps the
 * LLM-facing tool name back to the connector + URL + original
 * tool name so executeBuiltinTool can call the right MCP server.
 */
interface MCPToolRoute {
  connectorId: string;
  url: string;
  token: string | null;
  originalName: string;
}

/**
 * Context passed to executeBuiltinTool. Carries the MCP routing table
 * plus a getSandbox closure so the engine can lazily provision a
 * sandbox only when a tool actually requests one.
 */
export interface ToolExecutionContext {
  mcpRoutes?: Map<string, MCPToolRoute>;
  getSandbox?: () => Promise<Sandbox>;
}

export interface ResolvedTools {
  tools: ToolDefinition[];
  mcpRoutes: Map<string, MCPToolRoute>;
}

/**
 * Resolves tool definitions from agent config.
 *
 * Built-in + custom tools are returned unchanged. For every entry in
 * agentConfig.mcp_servers we open a short-lived MCP connection
 * (StreamableHTTPClientTransport + Bearer from mcp_connections) and
 * list the server's real tools. Each remote tool is added to the
 * LLM's tool list with a `__mcp__<connector>__<tool>` prefix and
 * a matching entry in `mcpRoutes` so callMCPTool() can route a tool
 * call back to the right server.
 *
 * If a connector fails (no token stored, unreachable, 401, …) we log
 * the reason and skip it. The agent still runs with whatever tools
 * did resolve rather than erroring out the whole turn.
 */
export async function resolveTools(
  agentConfig: AgentConfig,
  organizationId: string,
): Promise<ResolvedTools> {
  const tools: ToolDefinition[] = [];
  const mcpRoutes = new Map<string, MCPToolRoute>();

  for (const tool of agentConfig.tools) {
    if (tool.type === "agent_toolset_20260401") {
      tools.push(...AGENT_TOOLS);
    } else if (tool.type === "custom") {
      tools.push({
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema ?? { type: "object", properties: {} },
      });
    }
  }

  for (const mcp of agentConfig.mcp_servers ?? []) {
    const connectorId = String(mcp.name ?? "");
    const url = String(mcp.url ?? "");
    if (!connectorId || !url) continue;

    let token: string | null = null;
    try {
      token = await loadConnectorToken(organizationId, connectorId);
    } catch (err) {
      console.warn(
        `[engine] failed to load token for ${connectorId}:`,
        err instanceof Error ? err.message : err,
      );
      continue;
    }

    try {
      const remoteTools = await listMCPTools(url, token);
      for (const t of remoteTools) {
        const prefixed = `__mcp__${connectorId}__${t.name}`;
        tools.push({
          name: prefixed,
          description: t.description
            ? `[${connectorId}] ${t.description}`
            : `[${connectorId}] ${t.name}`,
          input_schema: t.input_schema,
        });
        mcpRoutes.set(prefixed, {
          connectorId,
          url,
          token,
          originalName: t.name,
        });
      }
    } catch (err) {
      const msg =
        err instanceof MCPClientError
          ? `${err.type}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err);
      console.warn(
        `[engine] skipping MCP connector ${connectorId} (${url}): ${msg}`,
      );
      // Fall through — the agent keeps running with the tools we did
      // resolve. A degraded-but-working agent is better than a hard
      // failure mid-turn.
    }
  }

  return { tools, mcpRoutes };
}

/**
 * Execute a built-in tool and return the result.
 *
 * If the tool name starts with `__mcp__<connector>__`, it's routed
 * through the MCP client using the matching route from resolveTools.
 */
export async function executeBuiltinTool(
  name: string,
  input: Record<string, unknown>,
  ctx?: ToolExecutionContext,
): Promise<{ content: string; is_error: boolean }> {
  const mcpRoutes = ctx?.mcpRoutes;
  try {
    // ── Remote MCP tool ──────────────────────────────────────────
    if (name.startsWith("__mcp__") && mcpRoutes?.has(name)) {
      const route = mcpRoutes.get(name)!;
      try {
        const result = await callMCPTool(
          route.url,
          route.token,
          route.originalName,
          input,
        );
        const text = (result.content ?? [])
          .filter((p) => p.type === "text" && typeof p.text === "string")
          .map((p) => p.text!)
          .join("\n")
          .trim();
        return {
          content: text || JSON.stringify(result.content ?? []),
          is_error: result.is_error === true,
        };
      } catch (err) {
        const msg =
          err instanceof MCPClientError
            ? `${err.type}: ${err.message}`
            : err instanceof Error
              ? err.message
              : String(err);
        return {
          content: `MCP call failed (${route.connectorId}.${route.originalName}): ${msg}`,
          is_error: true,
        };
      }
    }

    if (name === "bash") {
      if (!ctx?.getSandbox) {
        return {
          content:
            "bash tool unavailable: no sandbox factory configured. Set DAYTONA_API_KEY or run in a non-production environment.",
          is_error: true,
        };
      }
      const command = String((input as { command?: unknown }).command ?? "");
      const timeoutSec = Number(
        (input as { timeout_seconds?: unknown }).timeout_seconds ?? 60,
      );
      if (!command) {
        return {
          content: "bash: missing 'command' parameter.",
          is_error: true,
        };
      }
      const sandbox = await ctx.getSandbox();
      const r = await sandbox.exec(command, { timeoutSec });
      const parts: string[] = [];
      if (r.stdout) parts.push(r.stdout);
      if (r.stderr) parts.push(`[stderr]\n${r.stderr}`);
      parts.push(`[exit code: ${r.exitCode}]`);
      return {
        content: parts.join("\n").trim(),
        is_error: r.exitCode !== 0,
      };
    }

    if (name === "read_file") {
      if (!ctx?.getSandbox) {
        return {
          content: "read_file unavailable: no sandbox factory configured.",
          is_error: true,
        };
      }
      const path = String((input as { path?: unknown }).path ?? "");
      if (!path) {
        return { content: "read_file: missing 'path' parameter.", is_error: true };
      }
      try {
        const sandbox = await ctx.getSandbox();
        const content = await sandbox.readFile(path);
        const { text } = truncateOutput(content);
        return { content: text, is_error: false };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: `read_file failed: ${msg}`, is_error: true };
      }
    }

    if (name === "write_file") {
      if (!ctx?.getSandbox) {
        return {
          content: "write_file unavailable: no sandbox factory configured.",
          is_error: true,
        };
      }
      const path = String((input as { path?: unknown }).path ?? "");
      const content = String((input as { content?: unknown }).content ?? "");
      if (!path) {
        return { content: "write_file: missing 'path' parameter.", is_error: true };
      }
      try {
        const sandbox = await ctx.getSandbox();
        // Ensure parent dir exists. Last slash defines the dir; if there
        // isn't one, the file lives at the sandbox root and we skip mkdir.
        const lastSlash = path.lastIndexOf("/");
        if (lastSlash > 0) {
          const dir = path.slice(0, lastSlash);
          await sandbox.exec(`mkdir -p ${shellEscape(dir)}`);
        }
        await sandbox.writeFile(path, content);
        return {
          content: `Wrote ${content.length} bytes to ${path}`,
          is_error: false,
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: `write_file failed: ${msg}`, is_error: true };
      }
    }

    if (name === "edit_file") {
      if (!ctx?.getSandbox) {
        return {
          content: "edit_file unavailable: no sandbox factory configured.",
          is_error: true,
        };
      }
      const path = String((input as { path?: unknown }).path ?? "");
      const oldString = String((input as { old_string?: unknown }).old_string ?? "");
      const newString = String((input as { new_string?: unknown }).new_string ?? "");
      const replaceAll = Boolean(
        (input as { replace_all?: unknown }).replace_all ?? false,
      );
      if (!path) {
        return { content: "edit_file: missing 'path' parameter.", is_error: true };
      }
      if (!oldString) {
        return {
          content: "edit_file: missing 'old_string' parameter.",
          is_error: true,
        };
      }
      try {
        const sandbox = await ctx.getSandbox();
        const original = await sandbox.readFile(path);
        let updated: string;
        let occurrences: number;
        if (replaceAll) {
          // Cheap occurrence count without regex (avoids escaping).
          occurrences = original.split(oldString).length - 1;
          if (occurrences === 0) {
            return {
              content: `edit_file: old_string not found in ${path}`,
              is_error: true,
            };
          }
          updated = original.split(oldString).join(newString);
        } else {
          const first = original.indexOf(oldString);
          if (first === -1) {
            return {
              content: `edit_file: old_string not found in ${path}`,
              is_error: true,
            };
          }
          if (original.indexOf(oldString, first + oldString.length) !== -1) {
            return {
              content: `edit_file: old_string appears multiple times in ${path}. Add surrounding context to make it unique, or pass replace_all=true.`,
              is_error: true,
            };
          }
          updated = original.replace(oldString, newString);
          occurrences = 1;
        }
        await sandbox.writeFile(path, updated);
        return {
          content: `Edited ${path} (${occurrences} replacement${occurrences === 1 ? "" : "s"})`,
          is_error: false,
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: `edit_file failed: ${msg}`, is_error: true };
      }
    }

    if (name === "web_search") {
      // Simple web search implementation
      const query = input.query as string;
      return {
        content: `Web search results for "${query}":\n\n(Web search is available when connected to a search provider. Configure a web search MCP server or API key to enable live results.)`,
        is_error: false,
      };
    }
    if (name === "web_fetch") {
      const url = input.url as string;
      try {
        const response = await fetch(url, {
          headers: { "User-Agent": "OpenManagedAgents/0.1.0" },
          signal: AbortSignal.timeout(30000),
        });
        const text = await response.text();
        // Truncate to avoid huge responses
        const truncated = text.length > 10000 ? text.slice(0, 10000) + "\n\n[... truncated]" : text;
        return { content: truncated, is_error: false };
      } catch (err: any) {
        return { content: `Failed to fetch ${url}: ${err.message}`, is_error: true };
      }
    }

    return {
      content: `Unknown tool: ${name}`,
      is_error: true,
    };
  } catch (err: any) {
    return {
      content: `Tool execution error: ${err.message}`,
      is_error: true,
    };
  }
}

/**
 * Store an event in the database and return it.
 */
async function storeEvent(
  sessionId: string,
  type: string,
  data: Record<string, unknown>
): Promise<SessionEventData> {
  const db = await getDB();
  const id = newId("evt");
  const processed_at = new Date().toISOString();
  const event: SessionEventData = { id, type, ...data, processed_at };

  await db.run(
    "INSERT INTO events (id, session_id, type, data, processed_at) VALUES (?, ?, ?, ?, ?)",
    id, sessionId, type, JSON.stringify(data), processed_at
  );

  return event;
}

/**
 * Update session status in the database.
 */
async function updateSessionStatus(sessionId: string, status: string) {
  const db = await getDB();
  await db.run(
    "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
    status, new Date().toISOString(), sessionId
  );
}

/**
 * Update session usage stats.
 */
async function updateSessionUsage(
  sessionId: string,
  inputTokens: number,
  outputTokens: number,
  cacheRead: number,
  _cacheWrite: number
) {
  const db = await getDB();
  const session = await db.get<any>("SELECT usage, stats FROM sessions WHERE id = ?", sessionId);
  if (!session) return;

  const usage = JSON.parse(session.usage || "{}");
  const stats = JSON.parse(session.stats || "{}");

  usage.input_tokens = (usage.input_tokens ?? 0) + inputTokens;
  usage.output_tokens = (usage.output_tokens ?? 0) + outputTokens;
  usage.cache_read_input_tokens = (usage.cache_read_input_tokens ?? 0) + cacheRead;

  await db.run(
    "UPDATE sessions SET usage = ?, stats = ?, updated_at = ? WHERE id = ?",
    JSON.stringify(usage), JSON.stringify(stats), new Date().toISOString(), sessionId
  );
}

/**
 * Build conversation messages from stored events for a session.
 */
async function buildMessagesFromEvents(sessionId: string): Promise<ChatMessage[]> {
  const db = await getDB();
  const events = await db.all<{ type: string; data: string }>(
    "SELECT type, data FROM events WHERE session_id = ? ORDER BY processed_at ASC",
    sessionId
  );

  const messages: ChatMessage[] = [];

  for (const evt of events) {
    const data = JSON.parse(evt.data);

    if (evt.type === "user.message") {
      const text = (data.content ?? [])
        .filter((b: any) => b.type === "text")
        .map((b: any) => b.text)
        .join("");
      if (text) {
        messages.push({ role: "user", content: text });
      }
    } else if (evt.type === "agent.message") {
      const text = (data.content ?? [])
        .filter((b: any) => b.type === "text")
        .map((b: any) => b.text)
        .join("");
      if (text) {
        // Check if there are subsequent tool_use events that belong to this turn
        messages.push({ role: "assistant", content: text });
      }
    } else if (evt.type === "agent.tool_use") {
      // Add tool_use as part of assistant message
      const last = messages[messages.length - 1];
      if (last?.role === "assistant") {
        if (typeof last.content === "string") {
          last.content = [
            { type: "text", text: last.content },
            { type: "tool_use", id: data.tool_use_id ?? data.id, name: data.name, input: data.input ?? {} },
          ];
        } else if (Array.isArray(last.content)) {
          last.content.push({
            type: "tool_use",
            id: data.tool_use_id ?? data.id,
            name: data.name,
            input: data.input ?? {},
          });
        }
      } else {
        messages.push({
          role: "assistant",
          content: [
            { type: "tool_use", id: data.tool_use_id ?? data.id, name: data.name, input: data.input ?? {} },
          ],
        });
      }
    } else if (evt.type === "agent.tool_result") {
      const resultText = (data.content ?? [])
        .filter((b: any) => b.type === "text")
        .map((b: any) => b.text)
        .join("");
      messages.push({
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: data.tool_use_id,
            content: resultText,
            is_error: data.is_error ?? false,
          },
        ],
      });
    }
  }

  return messages;
}

/**
 * Run the agent loop for a session. Processes a single user turn:
 * calls the LLM, processes tool calls, loops until done or max iterations.
 */
export async function runAgentLoop(
  sessionId: string,
  agentConfig: AgentConfig,
  provider: LLMProvider,
  emitter?: SessionEventEmitter,
  maxIterations = 20,
  organizationId = "org_default",
  sandboxFactory?: SandboxFactory,
): Promise<void> {
  const { tools, mcpRoutes } = await resolveTools(agentConfig, organizationId);
  let iteration = 0;

  // Lazily-provisioned sandbox: created the first time a tool actually
  // calls getSandbox(), torn down in the finally below.
  // KNOWN LIMITATION: state does not persist across turns in a session
  // — each runAgentLoop invocation gets its own. Follow-up PR: store
  // sandbox_id on the session row and reuse it on subsequent turns.
  let sandbox: Sandbox | undefined;
  const getSandbox = async (): Promise<Sandbox> => {
    if (!sandbox) {
      if (!sandboxFactory) {
        throw new Error(
          "no SandboxFactory provided to runAgentLoop — bash and other sandboxed tools cannot run",
        );
      }
      sandbox = await sandboxFactory.create();
    }
    return sandbox;
  };

  // Mark session as running
  await updateSessionStatus(sessionId, "running");
  const runningEvent = await storeEvent(sessionId, "session.status_running", {});
  emitter?.emit(runningEvent);

  try {
    while (iteration < maxIterations) {
      iteration++;

      // Cooperative cancellation: check the session status before
      // each LLM call. If a user clicked Stop on the UI (or anything
      // else POSTed /v1/sessions/:id/stop), the row has been flipped
      // to "terminated" — bail out of the loop without firing another
      // provider.chat(). The in-flight call from the previous
      // iteration has already finished; the next one never runs.
      const db = await getDB();
      const statusRow = await db.get<{ status: string }>(
        "SELECT status FROM sessions WHERE id = ?",
        sessionId,
      );
      if (statusRow?.status === "terminated") {
        // Emit session.status_terminated — a declared event type
        // that the UI already maps via EVENT_BADGES. The prior
        // implementation emitted "session.stopped" which isn't on
        // the SessionEvent union in packages/types/src/events.ts,
        // so the client's switch/case fell through to a default
        // grey badge and the badge on the list view only updated
        // when the 5s polling query refetched the session row.
        // With a declared status event on the SSE stream, the
        // badge flips immediately.
        const terminatedEvent = await storeEvent(
          sessionId,
          "session.status_terminated",
          {},
        );
        emitter?.emit(terminatedEvent);
        return;
      }

      // Build messages from stored events
      const messages = await buildMessagesFromEvents(sessionId);

      if (messages.length === 0) break;

      // Emit model request start
      const startEvent = await storeEvent(sessionId, "span.model_request_start", {});
      emitter?.emit(startEvent);

      // Call the LLM
      const result = await provider.chat({
        model: agentConfig.model,
        system: agentConfig.system ?? undefined,
        messages,
        tools: tools.length > 0 ? tools : undefined,
      });

      // Emit model request end with usage
      const endEvent = await storeEvent(sessionId, "span.model_request_end", {
        model_request_start_id: startEvent.id,
        model_usage: {
          input_tokens: result.usage.input_tokens,
          output_tokens: result.usage.output_tokens,
          cache_read_input_tokens: result.usage.cache_read_input_tokens ?? 0,
          cache_creation_input_tokens: result.usage.cache_creation_input_tokens ?? 0,
        },
        is_error: false,
      });
      emitter?.emit(endEvent);

      // Update session usage
      await updateSessionUsage(
        sessionId,
        result.usage.input_tokens,
        result.usage.output_tokens,
        result.usage.cache_read_input_tokens ?? 0,
        result.usage.cache_creation_input_tokens ?? 0
      );

      // Process response content
      const textParts = result.content.filter((p) => p.type === "text");
      const toolUseParts = result.content.filter((p) => p.type === "tool_use");

      // Emit text response as agent message
      if (textParts.length > 0) {
        const agentMsg = await storeEvent(sessionId, "agent.message", {
          content: textParts.map((p) => ({ type: "text", text: p.text })),
        });
        emitter?.emit(agentMsg);
      }

      // If no tool calls, we're done
      if (result.stop_reason !== "tool_use" || toolUseParts.length === 0) {
        break;
      }

      // Process tool calls
      for (const toolUse of toolUseParts) {
        // Emit tool use event
        const toolUseEvent = await storeEvent(sessionId, "agent.tool_use", {
          tool_use_id: toolUse.id,
          name: toolUse.name,
          input: toolUse.input,
          evaluated_permission: "allow",
        });
        emitter?.emit(toolUseEvent);

        // Check if it's a custom tool (needs user response)
        const isCustom = agentConfig.tools.some(
          (t: any) => t.type === "custom" && t.name === toolUse.name
        );

        if (isCustom) {
          // Emit custom tool use event - user needs to provide result
          await storeEvent(sessionId, "agent.custom_tool_use", {
            name: toolUse.name,
            input: toolUse.input,
          });
          // Go idle waiting for user to provide tool result
          await updateSessionStatus(sessionId, "idle");
          const idleEvent = await storeEvent(sessionId, "session.status_idle", {
            stop_reason: {
              type: "requires_action",
              event_ids: [toolUseEvent.id],
            },
          });
          emitter?.emit(idleEvent);
          return;
        }

        // Execute built-in or routed-MCP tool
        const toolResult = await executeBuiltinTool(
          toolUse.name!,
          toolUse.input ?? {},
          { mcpRoutes, getSandbox },
        );

        // Store tool result
        const toolResultEvent = await storeEvent(sessionId, "agent.tool_result", {
          tool_use_id: toolUse.id,
          content: [{ type: "text", text: toolResult.content }],
          is_error: toolResult.is_error,
        });
        emitter?.emit(toolResultEvent);
      }

      // Continue loop for next LLM call
    }

    // Mark session as idle
    await updateSessionStatus(sessionId, "idle");
    const idleEvent = await storeEvent(sessionId, "session.status_idle", {
      stop_reason: { type: "end_turn" },
    });
    emitter?.emit(idleEvent);
  } catch (err: any) {
    console.error(`Agent loop error for session ${sessionId}:`, err);

    const errorEvent = await storeEvent(sessionId, "session.error", {
      error: {
        type: "unknown_error",
        message: err.message ?? "Unknown error",
        retry_status: { type: "terminal" },
      },
    });
    emitter?.emit(errorEvent);

    // Mark the session terminated — NOT idle. The previous
    // behavior ran updateSessionStatus(..., "idle") + emitted
    // session.status_idle with stop_reason end_turn, which made
    // a failed session indistinguishable from a successful one
    // in the UI (same green "idle" badge, same "end_turn" in the
    // stop reason). A terminated badge renders in red via the
    // statusVariant map, so operators can see at a glance that
    // the run failed.
    await updateSessionStatus(sessionId, "terminated");
    const terminatedEvent = await storeEvent(
      sessionId,
      "session.status_terminated",
      {},
    );
    emitter?.emit(terminatedEvent);
  } finally {
    if (sandbox) {
      await sandbox.destroy();
    }
  }
}

/**
 * Create a streaming event emitter backed by a ReadableStream for SSE.
 */
export function createSSEEmitter(): {
  emitter: SessionEventEmitter;
  stream: ReadableStream;
} {
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
  });

  const emitter: SessionEventEmitter = {
    emit(event: SessionEventData) {
      try {
        const data = `data: ${JSON.stringify(event)}\n\n`;
        controller.enqueue(encoder.encode(data));
      } catch {
        // Stream may be closed
      }
    },
    close() {
      try {
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      } catch {
        // Already closed
      }
    },
  };

  return { emitter, stream };
}
