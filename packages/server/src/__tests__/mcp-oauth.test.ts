/**
 * OAuth authorization-code flow for MCP connectors.
 *
 * The provider's token endpoint is stubbed via global.fetch so the
 * test exercises:
 *   - /oauth/authorize stores a state row + returns the authorize URL
 *   - 503 when client credentials env vars are missing
 *   - 404 for an unknown connector
 *   - /oauth/callback exchanges the code, decrypts the token, stores
 *     it in mcp_connections, and 302s to the redirect_after path
 *   - replay protection: a consumed state row cannot be reused
 *   - expired states are rejected
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { beforeAll, afterAll, describe, it, expect, beforeEach, vi } from "vitest";

const tmpDir = mkdtempSync(join(tmpdir(), "oma-mcp-oauth-test-"));
process.env.DATABASE_PATH = join(tmpDir, "oma.db");
process.env.AUTH_ENABLED = "false";
process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString("hex");
process.env.NOTION_OAUTH_CLIENT_ID = "test_client_id";
process.env.NOTION_OAUTH_CLIENT_SECRET = "test_client_secret";
process.env.OAUTH_CALLBACK_BASE_URL = "http://localhost:3001";

const { createApp } = await import("../app.js");
const { getDB } = await import("../db/index.js");
const { decrypt } = await import("../lib/encryption.js");

let app: Awaited<ReturnType<typeof createApp>>;
let fetchSpy: ReturnType<typeof vi.spyOn>;

beforeAll(async () => {
  app = await createApp({ skipProviderSeed: true });
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(async () => {
  const db = await getDB();
  await db.run("DELETE FROM mcp_connections");
  await db.run("DELETE FROM oauth_states");
  fetchSpy = vi.spyOn(globalThis, "fetch");
});

describe("GET /v1/mcp/connectors/:id/oauth/authorize", () => {
  it("returns an authorize URL and stores a state row for Notion", async () => {
    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize?redirect_after=/quickstart",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      authorize_url: string;
      state: string;
    };

    expect(body.state).toBeTruthy();
    const url = new URL(body.authorize_url);
    expect(url.origin + url.pathname).toBe(
      "https://api.notion.com/v1/oauth/authorize",
    );
    expect(url.searchParams.get("client_id")).toBe("test_client_id");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("state")).toBe(body.state);
    expect(url.searchParams.get("owner")).toBe("user");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3001/v1/mcp/connectors/notion/oauth/callback",
    );

    const db = await getDB();
    const row = await db.get<{
      connector_id: string;
      redirect_after: string;
    }>("SELECT connector_id, redirect_after FROM oauth_states WHERE state = ?", body.state);
    expect(row?.connector_id).toBe("notion");
    expect(row?.redirect_after).toBe("/quickstart");
  });

  it("returns 503 when client credentials env vars are missing", async () => {
    const savedId = process.env.NOTION_OAUTH_CLIENT_ID;
    const savedSecret = process.env.NOTION_OAUTH_CLIENT_SECRET;
    delete process.env.NOTION_OAUTH_CLIENT_ID;
    delete process.env.NOTION_OAUTH_CLIENT_SECRET;

    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize",
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as {
      error: { type: string; message: string };
    };
    expect(body.error.type).toBe("oauth_credentials_missing");
    expect(body.error.message).toContain("NOTION_OAUTH_CLIENT_ID");

    process.env.NOTION_OAUTH_CLIENT_ID = savedId;
    process.env.NOTION_OAUTH_CLIENT_SECRET = savedSecret;
  });

  it("returns 404 for an unknown connector", async () => {
    const res = await app.request(
      "/v1/mcp/connectors/totally-fake/oauth/authorize",
    );
    expect(res.status).toBe(404);
  });

  it("returns 503 for a known connector that has no OAUTH_PROVIDERS entry", async () => {
    // Stripe is in CONNECTORS (auth_type: token), not in OAUTH_PROVIDERS.
    const res = await app.request(
      "/v1/mcp/connectors/stripe/oauth/authorize",
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as {
      error: { type: string };
    };
    expect(body.error.type).toBe("oauth_not_supported");
  });
});

describe("GET /v1/mcp/connectors/:id/oauth/callback", () => {
  async function primeStateRow(): Promise<{ state: string }> {
    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize?redirect_after=/quickstart",
    );
    const body = (await res.json()) as { state: string };
    return { state: body.state };
  }

  it("exchanges code, stores encrypted token, deletes state, 302s back to redirect_after", async () => {
    const { state } = await primeStateRow();

    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "notion-secret-abc123",
          workspace_id: "ws_xyz",
          workspace_name: "Test workspace",
          bot_id: "bot_test",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=auth-code-1&state=${state}`,
      { redirect: "manual" },
    );

    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toMatch(/^\/quickstart\?/);
    expect(location).toContain("oauth_success=1");
    expect(location).toContain("oauth_connector=notion");

    // ── State row consumed ─────────────────────────────────────
    const db = await getDB();
    const stateRow = await db.get(
      "SELECT * FROM oauth_states WHERE state = ?",
      state,
    );
    expect(stateRow).toBeFalsy();

    // ── mcp_connections has the encrypted token ────────────────
    const connRow = await db.get<{
      connector_id: string;
      auth_type: string;
      token_encrypted: string;
      refresh_token_encrypted: string | null;
      expires_at: string | null;
    }>(
      "SELECT connector_id, auth_type, token_encrypted, refresh_token_encrypted, expires_at FROM mcp_connections WHERE connector_id = ?",
      "notion",
    );
    expect(connRow?.connector_id).toBe("notion");
    expect(connRow?.auth_type).toBe("oauth");
    expect(decrypt(connRow!.token_encrypted)).toBe("notion-secret-abc123");
    expect(connRow?.refresh_token_encrypted).toBeNull();
    expect(connRow?.expires_at).toBeNull();

    // ── Notion's token endpoint received the right call ────────
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchSpy.mock.calls[0]! as [
      string,
      RequestInit,
    ];
    expect(calledUrl).toBe("https://api.notion.com/v1/oauth/token");
    expect((calledInit.headers as Record<string, string>)["Authorization"]).toBe(
      `Basic ${Buffer.from("test_client_id:test_client_secret").toString("base64")}`,
    );
    expect(
      (calledInit.headers as Record<string, string>)["Notion-Version"],
    ).toBe("2022-06-28");
    const sentBody = JSON.parse(calledInit.body as string) as {
      grant_type: string;
      code: string;
      redirect_uri: string;
    };
    expect(sentBody.grant_type).toBe("authorization_code");
    expect(sentBody.code).toBe("auth-code-1");
    expect(sentBody.redirect_uri).toBe(
      "http://localhost:3001/v1/mcp/connectors/notion/oauth/callback",
    );
  });

  it("rejects a replay — same state used twice", async () => {
    const { state } = await primeStateRow();

    fetchSpy.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // First callback succeeds + consumes state
    const first = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=c1&state=${state}`,
      { redirect: "manual" },
    );
    expect(first.status).toBe(302);
    expect(first.headers.get("Location") ?? "").toContain("oauth_success=1");

    // Second use of the same state must fail
    const second = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=c2&state=${state}`,
      { redirect: "manual" },
    );
    expect(second.status).toBe(302);
    expect(second.headers.get("Location") ?? "").toContain(
      "oauth_error=invalid_state",
    );
  });

  it("rejects an expired state row", async () => {
    const { state } = await primeStateRow();
    const db = await getDB();
    await db.run(
      "UPDATE oauth_states SET expires_at = ? WHERE state = ?",
      "2020-01-01T00:00:00.000Z",
      state,
    );

    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=c&state=${state}`,
      { redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=state_expired",
    );
  });

  it("surfaces a provider-side error in the redirect", async () => {
    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?error=access_denied&error_description=User+declined`,
      { redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=access_denied",
    );
  });

  it("surfaces a token-exchange failure as an oauth_error redirect", async () => {
    const { state } = await primeStateRow();
    fetchSpy.mockResolvedValueOnce(
      new Response('{"error":"invalid_grant"}', {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=bad&state=${state}`,
      { redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=token_exchange_failed",
    );
  });
});
