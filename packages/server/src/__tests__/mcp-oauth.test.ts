/**
 * MCP-spec OAuth flow: discovery (RFC 8414) + Dynamic Client Registration
 * (RFC 7591) + Authorization Code + PKCE.
 *
 * All outbound HTTP to the MCP server (discovery / register / token) is
 * mocked via global.fetch so the tests don't hit Notion or any real
 * provider. Coverage:
 *
 *   - /oauth/authorize end-to-end: discovers, registers, caches client,
 *     stores state row, returns an authorize URL pointing at the
 *     DISCOVERED endpoint with PKCE.
 *   - Cache reuse: a second /oauth/authorize call for the same
 *     (org, connector) does NOT re-hit discovery or registration.
 *   - Discovery failure surfaces as 503 with a clear error type.
 *   - Registration failure surfaces as 503.
 *   - 404 / 400 for unknown / non-oauth connectors.
 *   - /oauth/callback exchanges code at the discovered token endpoint
 *     with PKCE verifier, stores encrypted token, 302s back.
 *   - Replay protection (consumed state cannot be reused).
 *   - Expired state rejected.
 *   - Provider-side error in the redirect surfaced.
 *   - Token-exchange failure surfaced.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  beforeAll,
  afterAll,
  describe,
  it,
  expect,
  beforeEach,
  vi,
} from "vitest";

const tmpDir = mkdtempSync(join(tmpdir(), "oma-mcp-oauth-test-"));
process.env.DATABASE_PATH = join(tmpDir, "oma.db");
process.env.AUTH_ENABLED = "false";
process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString("hex");
process.env.OAUTH_CALLBACK_BASE_URL = "http://localhost:5173";

const { createApp } = await import("../app.js");
const { getDB } = await import("../db/index.js");
const { decrypt } = await import("../lib/encryption.js");

let app: Awaited<ReturnType<typeof createApp>>;
let fetchSpy: ReturnType<typeof vi.spyOn>;

const DISCOVERY_DOC = {
  issuer: "https://mcp.notion.com",
  authorization_endpoint: "https://mcp.notion.com/authorize",
  token_endpoint: "https://mcp.notion.com/token",
  registration_endpoint: "https://mcp.notion.com/register",
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
};

function mockDiscovery() {
  return new Response(JSON.stringify(DISCOVERY_DOC), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function mockRegistration(opts: { clientId?: string; clientSecret?: string } = {}) {
  return new Response(
    JSON.stringify({
      client_id: opts.clientId ?? "dyn-client-1",
      ...(opts.clientSecret ? { client_secret: opts.clientSecret } : {}),
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

function mockTokenSuccess(accessToken = "notion-secret-abc123") {
  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "Bearer",
      workspace_id: "ws_xyz",
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

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
  await db.run("DELETE FROM mcp_oauth_clients");
  fetchSpy = vi.spyOn(globalThis, "fetch");
});

describe("GET /v1/mcp/connectors/:id/oauth/authorize (discovery + dynamic registration)", () => {
  it("discovers, registers, caches the client, and returns an authorize URL", async () => {
    fetchSpy.mockResolvedValueOnce(mockDiscovery());
    fetchSpy.mockResolvedValueOnce(mockRegistration({ clientId: "dyn-abc" }));

    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize?redirect_after=/quickstart",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authorize_url: string; state: string };

    // Authorize URL points at the DISCOVERED endpoint, not Notion's app OAuth.
    const url = new URL(body.authorize_url);
    expect(url.origin + url.pathname).toBe("https://mcp.notion.com/authorize");
    expect(url.searchParams.get("client_id")).toBe("dyn-abc");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("state")).toBe(body.state);
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:5173/v1/mcp/connectors/notion/oauth/callback",
    );

    // State row was persisted with a PKCE verifier.
    const db = await getDB();
    const stateRow = await db.get<{ code_verifier: string }>(
      "SELECT code_verifier FROM oauth_states WHERE state = ?",
      body.state,
    );
    expect(stateRow?.code_verifier).toBeTruthy();

    // Client cache populated.
    const cached = await db.get<{ client_id: string; token_endpoint: string }>(
      "SELECT client_id, token_endpoint FROM mcp_oauth_clients WHERE connector_id = ?",
      "notion",
    );
    expect(cached?.client_id).toBe("dyn-abc");
    expect(cached?.token_endpoint).toBe("https://mcp.notion.com/token");

    // Verify which URLs got hit and in what order.
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect((fetchSpy.mock.calls[0]![0] as string)).toBe(
      "https://mcp.notion.com/.well-known/oauth-authorization-server",
    );
    expect((fetchSpy.mock.calls[1]![0] as string)).toBe(
      "https://mcp.notion.com/register",
    );
  });

  it("reuses the cached client on subsequent connects — no re-discovery, no re-register", async () => {
    fetchSpy.mockResolvedValueOnce(mockDiscovery());
    fetchSpy.mockResolvedValueOnce(mockRegistration({ clientId: "first-time-client" }));

    // First call → discover + register.
    const first = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize",
    );
    expect(first.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    // Second call → no additional fetches.
    fetchSpy.mockClear();
    const second = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize",
    );
    expect(second.status).toBe(200);
    expect(fetchSpy).not.toHaveBeenCalled();

    const url = new URL(((await second.json()) as { authorize_url: string }).authorize_url);
    expect(url.searchParams.get("client_id")).toBe("first-time-client");
  });

  it("returns 503 when the discovery document is unreachable", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("", { status: 404 }));

    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize",
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe("oauth_discovery_failed");
    expect(body.error.message).toContain("404");
  });

  it("returns 503 when dynamic registration fails", async () => {
    fetchSpy.mockResolvedValueOnce(mockDiscovery());
    fetchSpy.mockResolvedValueOnce(
      new Response('{"error":"invalid_client_metadata"}', { status: 400 }),
    );

    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize",
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("oauth_discovery_failed");
  });

  it("returns 404 for an unknown connector", async () => {
    const res = await app.request(
      "/v1/mcp/connectors/totally-fake/oauth/authorize",
    );
    expect(res.status).toBe(404);
  });

  it("returns 400 for a known connector that isn't tagged auth_type:oauth", async () => {
    // Stripe is in CONNECTORS with auth_type "token".
    const res = await app.request(
      "/v1/mcp/connectors/stripe/oauth/authorize",
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("not_an_oauth_connector");
  });
});

describe("GET /v1/mcp/connectors/:id/oauth/callback", () => {
  async function primeStateAndClient(): Promise<{ state: string }> {
    fetchSpy.mockResolvedValueOnce(mockDiscovery());
    fetchSpy.mockResolvedValueOnce(mockRegistration({ clientId: "cb-client" }));
    const res = await app.request(
      "/v1/mcp/connectors/notion/oauth/authorize?redirect_after=/quickstart",
    );
    const body = (await res.json()) as { state: string };
    return { state: body.state };
  }

  it("exchanges code at the discovered token endpoint with PKCE and stores the token", async () => {
    const { state } = await primeStateAndClient();
    fetchSpy.mockResolvedValueOnce(mockTokenSuccess("notion-real-access-tok"));

    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=auth-code-1&state=${state}`,
      { redirect: "manual" },
    );

    expect(res.status).toBe(302);
    const location = res.headers.get("Location") ?? "";
    expect(location).toMatch(/^\/quickstart\?/);
    expect(location).toContain("oauth_success=1");
    expect(location).toContain("oauth_connector=notion");

    // The token endpoint hit was the DISCOVERED one (not Notion's app OAuth).
    const tokenCall = fetchSpy.mock.calls.find(
      ([u]) => typeof u === "string" && u.endsWith("/token"),
    );
    expect(tokenCall).toBeTruthy();
    expect(tokenCall![0]).toBe("https://mcp.notion.com/token");

    const tokenInit = tokenCall![1] as RequestInit;
    const tokenBody = new URLSearchParams(tokenInit.body as string);
    // Public client path: client_id in body, no Authorization header
    expect(tokenBody.get("grant_type")).toBe("authorization_code");
    expect(tokenBody.get("code")).toBe("auth-code-1");
    expect(tokenBody.get("code_verifier")).toBeTruthy();
    expect(tokenBody.get("client_id")).toBe("cb-client");
    expect(tokenBody.get("redirect_uri")).toBe(
      "http://localhost:5173/v1/mcp/connectors/notion/oauth/callback",
    );

    // State row consumed.
    const db = await getDB();
    const stateRow = await db.get(
      "SELECT * FROM oauth_states WHERE state = ?",
      state,
    );
    expect(stateRow).toBeFalsy();

    // mcp_connections row stored with the access token decryptable.
    const connRow = await db.get<{
      token_encrypted: string;
      auth_type: string;
    }>(
      "SELECT token_encrypted, auth_type FROM mcp_connections WHERE connector_id = ?",
      "notion",
    );
    expect(connRow?.auth_type).toBe("oauth");
    expect(decrypt(connRow!.token_encrypted)).toBe("notion-real-access-tok");
  });

  it("rejects a replayed state", async () => {
    const { state } = await primeStateAndClient();
    fetchSpy.mockResolvedValue(mockTokenSuccess());

    const first = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=c1&state=${state}`,
      { redirect: "manual" },
    );
    expect(first.status).toBe(302);
    expect(first.headers.get("Location") ?? "").toContain("oauth_success=1");

    const second = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=c2&state=${state}`,
      { redirect: "manual" },
    );
    expect(second.headers.get("Location") ?? "").toContain(
      "oauth_error=invalid_state",
    );
  });

  it("rejects an expired state row", async () => {
    const { state } = await primeStateAndClient();
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
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=state_expired",
    );
  });

  it("surfaces a provider-side error in the redirect", async () => {
    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?error=access_denied&error_description=User+declined`,
      { redirect: "manual" },
    );
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=access_denied",
    );
  });

  it("surfaces a token-exchange failure as oauth_error", async () => {
    const { state } = await primeStateAndClient();
    fetchSpy.mockResolvedValueOnce(
      new Response('{"error":"invalid_grant"}', { status: 400 }),
    );

    const res = await app.request(
      `/v1/mcp/connectors/notion/oauth/callback?code=bad&state=${state}`,
      { redirect: "manual" },
    );
    expect(res.headers.get("Location") ?? "").toContain(
      "oauth_error=token_exchange_failed",
    );
  });
});
