/**
 * End-to-end smoke for the bash tool. Runs the real agent loop against
 * the live Anthropic API and a real Daytona Cloud sandbox, sends a
 * user turn that requires bash to answer, and asserts an
 * `agent.tool_use` event was emitted with name="bash" and the tool
 * result reflects sandbox stdout.
 *
 * Gated by ANTHROPIC_API_KEY + DAYTONA_API_KEY. To run:
 *   set -a; source ../../.env; set +a
 *   pnpm --filter @open-managed-agents/server test engine-bash-e2e
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { beforeAll, afterAll, describe, it, expect } from "vitest";

const tmpDir = mkdtempSync(join(tmpdir(), "oma-engine-bash-e2e-"));
process.env.DATABASE_PATH = join(tmpDir, "oma.db");
process.env.AUTH_ENABLED = "false";
process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString("hex");

// @ai-sdk/anthropic reads ANTHROPIC_BASE_URL and silently replaces
// the default https://api.anthropic.com/v1. Some dev shells (e.g.
// Claude Code's host) set this to a proxy that doesn't accept the
// /messages path → 404. Force the canonical default for this test.
delete process.env.ANTHROPIC_BASE_URL;

const HAS_KEYS =
  Boolean(process.env.ANTHROPIC_API_KEY) && Boolean(process.env.DAYTONA_API_KEY);

const { createApp } = await import("../app.js");
const { getDB, newId } = await import("../db/index.js");
const { runAgentLoop } = await import("../engine/index.js");
const { createProvider } = await import("../providers/index.js");
import type { AgentConfig } from "../engine/index.js";

let sessionId: string;

beforeAll(async () => {
  await createApp({ skipProviderSeed: true });
  const db = await getDB();
  sessionId = newId("sesn");
  const now = new Date().toISOString();
  await db.run(
    `INSERT INTO sessions (id, title, agent_id, agent_snapshot, environment_id, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    sessionId,
    "bash-e2e",
    "agent_e2e",
    JSON.stringify({ id: "agent_e2e", name: "e2e" }),
    "env_default",
    "idle",
    now,
    now,
  );
  await db.run(
    `INSERT INTO events (id, session_id, type, data, processed_at) VALUES (?, ?, ?, ?, ?)`,
    newId("evt"),
    sessionId,
    "user.message",
    JSON.stringify({
      content: [
        {
          type: "text",
          text:
            "Run the command `echo hello-from-sandbox-marker` using the bash tool. Then tell me exactly what stdout was.",
        },
      ],
    }),
    now,
  );
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe.skipIf(!HAS_KEYS)("runAgentLoop bash e2e (live)", () => {
  it("invokes the bash tool inside the Daytona sandbox and returns the stdout", async () => {
    const provider = createProvider({
      id: "anthropic-e2e",
      type: "anthropic",
      name: "Anthropic",
      apiKey: process.env.ANTHROPIC_API_KEY!,
    });

    const agentConfig: AgentConfig = {
      name: "e2e",
      system:
        "You have access to a sandboxed Linux environment via the `bash` tool. When the user asks you to run a command, ALWAYS use the bash tool — never simulate or guess output.",
      model: "claude-sonnet-4-6",
      tools: [{ type: "agent_toolset_20260401" }],
      mcp_servers: [],
      skills: [],
    };

    type Emitted = {
      type: string;
      name?: string;
      input?: unknown;
      content?: unknown;
      is_error?: boolean;
    };
    const emitted: Emitted[] = [];
    const emitter = {
      emit(event: Emitted) {
        emitted.push(event);
      },
      close() {},
    };

    const { DaytonaSandboxFactory } = await import("../sandbox/daytona.js");
    const sandboxFactory = new DaytonaSandboxFactory();

    await runAgentLoop(
      sessionId,
      agentConfig,
      provider,
      emitter,
      8,
      "org_default",
      sandboxFactory,
    );

    // ── At least one bash call ─────────────────────────────────────
    const bashCalls = emitted.filter(
      (e) => e.type === "agent.tool_use" && e.name === "bash",
    );
    expect(bashCalls.length, "agent should call bash at least once").toBeGreaterThan(0);

    // ── A matching tool result that's not an error ─────────────────
    const toolResults = emitted.filter((e) => e.type === "agent.tool_result");
    expect(toolResults.length).toBeGreaterThan(0);
    const successfulBash = toolResults.find((r) => r.is_error === false);
    expect(successfulBash, "at least one bash result should not be an error").toBeTruthy();

    // ── The result content reflects the actual sandbox stdout ──────
    const resultText = JSON.stringify(successfulBash?.content ?? "");
    expect(resultText).toContain("hello-from-sandbox-marker");
    expect(resultText).toContain("[exit code: 0]");

    // ── Session reaches a clean terminal state ─────────────────────
    const final = emitted[emitted.length - 1];
    expect(["session.status_idle", "session.status_terminated"]).toContain(
      final?.type ?? "",
    );
  }, 180_000);
});

if (!HAS_KEYS) {
  describe("runAgentLoop bash e2e (skipped)", () => {
    it("requires ANTHROPIC_API_KEY + DAYTONA_API_KEY to run live", () => {
      expect(HAS_KEYS).toBe(false);
    });
  });
}
