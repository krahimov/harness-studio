/**
 * Sandbox abstraction for running tools (bash, file ops) outside the
 * server process. Production uses Daytona Cloud; tests and dev without
 * a Daytona key fall back to LocalSandbox running on the host.
 *
 * Lifecycle for the initial integration: one sandbox per runAgentLoop
 * invocation, destroyed in the finally. State does NOT persist across
 * turns within a session — that's a known limitation slated for the
 * next PR (sandbox_id on session row + reuse on subsequent turns).
 */

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

export interface Sandbox {
  readonly id: string;
  exec(
    command: string,
    opts?: { cwd?: string; timeoutSec?: number },
  ): Promise<ExecResult>;
  readFile(path: string): Promise<string>;
  writeFile(path: string, content: string): Promise<void>;
  destroy(): Promise<void>;
}

export interface SandboxFactory {
  create(opts?: {
    image?: string;
    envVars?: Record<string, string>;
  }): Promise<Sandbox>;
}

export const STDOUT_CAP_BYTES = 100_000;

export function truncateOutput(s: string): { text: string; truncated: boolean } {
  const buf = Buffer.from(s, "utf8");
  if (buf.byteLength <= STDOUT_CAP_BYTES) return { text: s, truncated: false };
  const slice = buf.subarray(0, STDOUT_CAP_BYTES).toString("utf8");
  return {
    text: slice + "\n\n[... output truncated]",
    truncated: true,
  };
}

let cachedFactory: SandboxFactory | undefined;

/**
 * Resolve the SandboxFactory once per process. Order:
 *   1. DAYTONA_API_KEY set → DaytonaSandboxFactory
 *   2. NODE_ENV !== "production" → LocalSandboxFactory (host bash, loud warning)
 *   3. otherwise → throw
 *
 * Production deployments without Daytona credentials should fail
 * loudly rather than silently fall back to host execution.
 */
export async function getSandboxFactory(): Promise<SandboxFactory> {
  if (cachedFactory) return cachedFactory;

  if (process.env.DAYTONA_API_KEY) {
    const { DaytonaSandboxFactory } = await import("./daytona.js");
    cachedFactory = new DaytonaSandboxFactory();
    return cachedFactory;
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "DAYTONA_API_KEY is required in production. Refusing to run sandboxed tools on the host process.",
    );
  }

  console.warn(
    "[sandbox] DAYTONA_API_KEY not set — falling back to LocalSandbox (runs on host process). Dev/test only.",
  );
  const { LocalSandboxFactory } = await import("./local.js");
  cachedFactory = new LocalSandboxFactory();
  return cachedFactory;
}

/** Test-only — reset the cached factory between tests. */
export function _resetSandboxFactoryForTests(): void {
  cachedFactory = undefined;
}
