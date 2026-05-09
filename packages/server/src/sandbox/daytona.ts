/**
 * Daytona-backed Sandbox implementation.
 *
 * Wraps @daytonaio/sdk: client reads DAYTONA_API_KEY from env, create()
 * returns a Sandbox handle whose process.executeCommand and fs.{up,down}loadFile
 * we expose under our internal Sandbox interface.
 */

import { Daytona } from "@daytonaio/sdk";
import type {
  ExecResult,
  Sandbox,
  SandboxFactory,
} from "./index.js";
import { truncateOutput } from "./index.js";

type DaytonaClient = InstanceType<typeof Daytona>;
type DaytonaSDKSandbox = Awaited<ReturnType<DaytonaClient["create"]>>;

export class DaytonaSandboxFactory implements SandboxFactory {
  private client: DaytonaClient;

  constructor() {
    this.client = new Daytona();
  }

  async create(opts?: {
    image?: string;
    envVars?: Record<string, string>;
  }): Promise<Sandbox> {
    const params: Record<string, unknown> = {};
    if (opts?.envVars) params.envVars = opts.envVars;
    if (opts?.image) params.image = opts.image;
    const sdkSandbox = await this.client.create(params);
    return new DaytonaSandbox(sdkSandbox);
  }
}

class DaytonaSandbox implements Sandbox {
  readonly id: string;

  constructor(private sdk: DaytonaSDKSandbox) {
    this.id = sdk.id;
  }

  async exec(
    command: string,
    opts?: { cwd?: string; timeoutSec?: number },
  ): Promise<ExecResult> {
    const timeoutSec = opts?.timeoutSec ?? 60;
    const response = await this.sdk.process.executeCommand(
      command,
      opts?.cwd,
      undefined,
      timeoutSec,
    );

    const rawStdout =
      (response as { artifacts?: { stdout?: string }; result?: string })
        .artifacts?.stdout ??
      (response as { result?: string }).result ??
      "";
    const out = truncateOutput(rawStdout);

    return {
      exitCode: (response as { exitCode?: number }).exitCode ?? 0,
      stdout: out.text,
      // executeCommand merges stderr into the result stream. Separate
      // streams require executeSessionCommand; deferred until needed.
      stderr: "",
      truncated: out.truncated,
    };
  }

  async readFile(path: string): Promise<string> {
    const buf = await this.sdk.fs.downloadFile(path);
    return Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf);
  }

  async writeFile(path: string, content: string): Promise<void> {
    await this.sdk.fs.uploadFile(Buffer.from(content, "utf8"), path);
  }

  async destroy(): Promise<void> {
    try {
      await this.sdk.delete();
    } catch (err) {
      console.warn(
        `[sandbox] failed to delete Daytona sandbox ${this.id}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }
}
