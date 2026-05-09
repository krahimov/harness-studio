/**
 * LocalSandbox unit tests and a bash-tool dispatch test that exercises
 * executeBuiltinTool end-to-end against the LocalSandbox. No Daytona
 * required — these always run in CI.
 */

import { describe, it, expect, afterEach } from "vitest";
import { LocalSandboxFactory } from "../sandbox/local.js";
import { truncateOutput, STDOUT_CAP_BYTES } from "../sandbox/index.js";
import type { Sandbox } from "../sandbox/index.js";
import { executeBuiltinTool } from "../engine/index.js";

const created: Sandbox[] = [];

afterEach(async () => {
  while (created.length > 0) {
    const s = created.pop();
    if (s) await s.destroy().catch(() => {});
  }
});

async function spawnLocal(): Promise<Sandbox> {
  const factory = new LocalSandboxFactory();
  const s = await factory.create();
  created.push(s);
  return s;
}

describe("truncateOutput", () => {
  it("returns input unchanged when under the cap", () => {
    const r = truncateOutput("hello");
    expect(r.text).toBe("hello");
    expect(r.truncated).toBe(false);
  });

  it("truncates and flags when over the cap", () => {
    const big = "a".repeat(STDOUT_CAP_BYTES + 100);
    const r = truncateOutput(big);
    expect(r.truncated).toBe(true);
    expect(r.text.length).toBeLessThanOrEqual(STDOUT_CAP_BYTES + 100);
    expect(r.text.endsWith("[... output truncated]")).toBe(true);
  });
});

describe("LocalSandbox", () => {
  it("execs a simple command and returns stdout + exitCode 0", async () => {
    const s = await spawnLocal();
    const r = await s.exec("echo hello");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe("hello");
    expect(r.truncated).toBe(false);
  });

  it("returns non-zero exitCode and stderr for failing commands", async () => {
    const s = await spawnLocal();
    const r = await s.exec("ls /definitely-does-not-exist-xyz 2>&1 1>/dev/null; exit 7");
    expect(r.exitCode).toBe(7);
  });

  it("captures stderr separately", async () => {
    const s = await spawnLocal();
    const r = await s.exec(">&2 echo oops; echo ok");
    expect(r.stdout.trim()).toBe("ok");
    expect(r.stderr.trim()).toBe("oops");
    expect(r.exitCode).toBe(0);
  });

  it("writeFile + readFile roundtrip", async () => {
    const s = await spawnLocal();
    await s.writeFile("hello.txt", "world\n");
    const out = await s.readFile("hello.txt");
    expect(out).toBe("world\n");
  });

  it("kills the command on timeout and reports exit 124", async () => {
    const s = await spawnLocal();
    const r = await s.exec("sleep 5", { timeoutSec: 1 });
    expect(r.exitCode).toBe(124);
    expect(r.stderr).toContain("timed out");
  }, 10_000);

  it("destroys the temp dir on destroy()", async () => {
    const factory = new LocalSandboxFactory();
    const s = await factory.create();
    await s.writeFile("probe.txt", "x");
    await s.destroy();
    // After destroy the underlying file is gone — readFile should throw.
    await expect(s.readFile("probe.txt")).rejects.toThrow();
  });
});

describe("executeBuiltinTool('bash')", () => {
  it("dispatches to sandbox.exec via getSandbox and returns stdout+exit code", async () => {
    const s = await spawnLocal();
    const result = await executeBuiltinTool(
      "bash",
      { command: "echo from-bash-tool" },
      { getSandbox: async () => s },
    );
    expect(result.is_error).toBe(false);
    expect(result.content).toContain("from-bash-tool");
    expect(result.content).toContain("[exit code: 0]");
  });

  it("returns is_error=true and an unavailability message when no getSandbox is provided", async () => {
    const result = await executeBuiltinTool(
      "bash",
      { command: "echo hi" },
      {},
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("bash tool unavailable");
  });

  it("returns is_error=true when 'command' is missing", async () => {
    const s = await spawnLocal();
    const result = await executeBuiltinTool(
      "bash",
      {},
      { getSandbox: async () => s },
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("missing 'command'");
  });

  it("flags is_error=true when the command exits non-zero", async () => {
    const s = await spawnLocal();
    const result = await executeBuiltinTool(
      "bash",
      { command: "exit 3" },
      { getSandbox: async () => s },
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("[exit code: 3]");
  });
});

describe("executeBuiltinTool('read_file' / 'write_file')", () => {
  it("write_file then read_file roundtrip", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    const writeResult = await executeBuiltinTool(
      "write_file",
      { path: "hello.txt", content: "world\n" },
      ctx,
    );
    expect(writeResult.is_error).toBe(false);
    expect(writeResult.content).toContain("Wrote 6 bytes");

    const readResult = await executeBuiltinTool(
      "read_file",
      { path: "hello.txt" },
      ctx,
    );
    expect(readResult.is_error).toBe(false);
    expect(readResult.content).toBe("world\n");
  });

  it("write_file creates parent directories", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    const writeResult = await executeBuiltinTool(
      "write_file",
      { path: "nested/deep/file.txt", content: "ok" },
      ctx,
    );
    expect(writeResult.is_error).toBe(false);

    const readResult = await executeBuiltinTool(
      "read_file",
      { path: "nested/deep/file.txt" },
      ctx,
    );
    expect(readResult.content).toBe("ok");
  });

  it("read_file returns is_error=true on a missing file", async () => {
    const s = await spawnLocal();
    const result = await executeBuiltinTool(
      "read_file",
      { path: "nope.txt" },
      { getSandbox: async () => s },
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("read_file failed");
  });
});

describe("executeBuiltinTool('edit_file')", () => {
  it("replaces a single unique occurrence", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    await executeBuiltinTool(
      "write_file",
      { path: "code.txt", content: "alpha beta gamma" },
      ctx,
    );

    const result = await executeBuiltinTool(
      "edit_file",
      { path: "code.txt", old_string: "beta", new_string: "BETA" },
      ctx,
    );
    expect(result.is_error).toBe(false);
    expect(result.content).toContain("1 replacement");

    const after = await executeBuiltinTool("read_file", { path: "code.txt" }, ctx);
    expect(after.content).toBe("alpha BETA gamma");
  });

  it("refuses to edit when old_string appears multiple times without replace_all", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    await executeBuiltinTool(
      "write_file",
      { path: "dup.txt", content: "x x x" },
      ctx,
    );

    const result = await executeBuiltinTool(
      "edit_file",
      { path: "dup.txt", old_string: "x", new_string: "y" },
      ctx,
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("multiple times");
  });

  it("replace_all substitutes every occurrence", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    await executeBuiltinTool(
      "write_file",
      { path: "dup.txt", content: "x x x" },
      ctx,
    );

    const result = await executeBuiltinTool(
      "edit_file",
      {
        path: "dup.txt",
        old_string: "x",
        new_string: "y",
        replace_all: true,
      },
      ctx,
    );
    expect(result.is_error).toBe(false);
    expect(result.content).toContain("3 replacements");

    const after = await executeBuiltinTool("read_file", { path: "dup.txt" }, ctx);
    expect(after.content).toBe("y y y");
  });

  it("returns is_error=true when old_string is not found", async () => {
    const s = await spawnLocal();
    const ctx = { getSandbox: async () => s };

    await executeBuiltinTool(
      "write_file",
      { path: "f.txt", content: "hello" },
      ctx,
    );

    const result = await executeBuiltinTool(
      "edit_file",
      { path: "f.txt", old_string: "missing", new_string: "x" },
      ctx,
    );
    expect(result.is_error).toBe(true);
    expect(result.content).toContain("not found");
  });
});
