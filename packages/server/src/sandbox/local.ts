/**
 * Host-process Sandbox fallback. NOT a real sandbox — runs bash on the
 * host inside a temp working directory. Used only when DAYTONA_API_KEY
 * is missing AND NODE_ENV !== "production". Useful for tests and
 * Daytona-less local dev.
 */

import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { randomBytes } from "node:crypto";
import type { ExecResult, Sandbox, SandboxFactory } from "./index.js";
import { truncateOutput } from "./index.js";

export class LocalSandboxFactory implements SandboxFactory {
  async create(opts?: {
    image?: string;
    envVars?: Record<string, string>;
  }): Promise<Sandbox> {
    const dir = await mkdtemp(join(tmpdir(), "oma-sandbox-"));
    return new LocalSandbox(dir, opts?.envVars);
  }
}

class LocalSandbox implements Sandbox {
  readonly id: string;

  constructor(
    private rootDir: string,
    private envVars: Record<string, string> = {},
  ) {
    this.id = `local-${randomBytes(6).toString("hex")}`;
  }

  async exec(
    command: string,
    opts?: { cwd?: string; timeoutSec?: number },
  ): Promise<ExecResult> {
    const timeoutMs = (opts?.timeoutSec ?? 60) * 1000;
    const cwd = this.resolveCwd(opts?.cwd);

    return await new Promise<ExecResult>((resolve) => {
      const child = spawn("bash", ["-c", command], {
        cwd,
        env: { ...process.env, ...this.envVars },
      });

      let stdout = "";
      let stderr = "";
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);

      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString("utf8");
      });
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString("utf8");
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        const out = truncateOutput(stdout);
        const err = truncateOutput(stderr);
        const finalStderr = timedOut
          ? `${err.text}\n[command timed out after ${opts?.timeoutSec ?? 60}s]`
          : err.text;
        resolve({
          exitCode: timedOut ? 124 : (code ?? 0),
          stdout: out.text,
          stderr: finalStderr,
          truncated: out.truncated || err.truncated,
        });
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          exitCode: 1,
          stdout: "",
          stderr: `spawn error: ${err.message}`,
          truncated: false,
        });
      });
    });
  }

  async readFile(path: string): Promise<string> {
    return await fs.readFile(this.resolvePath(path), "utf8");
  }

  async writeFile(path: string, content: string): Promise<void> {
    await fs.writeFile(this.resolvePath(path), content, "utf8");
  }

  async destroy(): Promise<void> {
    try {
      await rm(this.rootDir, { recursive: true, force: true });
    } catch (err) {
      console.warn(
        `[sandbox] failed to clean up LocalSandbox dir ${this.rootDir}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  private resolveCwd(cwd: string | undefined): string {
    if (!cwd) return this.rootDir;
    return isAbsolute(cwd) ? cwd : join(this.rootDir, cwd);
  }

  private resolvePath(path: string): string {
    return isAbsolute(path) ? path : join(this.rootDir, path);
  }
}
