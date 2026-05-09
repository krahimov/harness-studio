/**
 * Daytona integration test. Gated by DAYTONA_API_KEY — skipped in CI
 * unless the secret is provisioned. Cold-start can take 10-30s on
 * Daytona Cloud, so the timeouts are generous.
 *
 * Run locally with:
 *   DAYTONA_API_KEY=... pnpm --filter @open-managed-agents/server test sandbox.daytona
 */

import { describe, it, expect, afterAll } from "vitest";
import type { Sandbox } from "../sandbox/index.js";

const HAS_KEY = Boolean(process.env.DAYTONA_API_KEY);

const created: Sandbox[] = [];

afterAll(async () => {
  while (created.length > 0) {
    const s = created.pop();
    if (s) await s.destroy().catch(() => {});
  }
});

describe.skipIf(!HAS_KEY)("DaytonaSandbox (live)", () => {
  it("creates a sandbox, runs echo hello, returns stdout + exit 0, destroys", async () => {
    const { DaytonaSandboxFactory } = await import("../sandbox/daytona.js");
    const factory = new DaytonaSandboxFactory();
    const s = await factory.create();
    created.push(s);

    expect(s.id).toBeTruthy();

    const r = await s.exec("echo hello");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("hello");
  }, 60_000);

  it("writeFile + readFile roundtrip via Daytona FS", async () => {
    const { DaytonaSandboxFactory } = await import("../sandbox/daytona.js");
    const factory = new DaytonaSandboxFactory();
    const s = await factory.create();
    created.push(s);

    await s.writeFile("/tmp/probe.txt", "from-daytona\n");
    const out = await s.readFile("/tmp/probe.txt");
    expect(out).toBe("from-daytona\n");
  }, 60_000);
});

if (!HAS_KEY) {
  describe("DaytonaSandbox (skipped)", () => {
    it("requires DAYTONA_API_KEY to run live", () => {
      expect(HAS_KEY).toBe(false);
    });
  });
}
