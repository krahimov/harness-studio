/**
 * OAuth routes for MCP connectors — discovery + dynamic-registration path.
 *
 * No per-provider env vars needed: the server discovers each MCP
 * server's OAuth endpoints from `.well-known/oauth-authorization-server`
 * (RFC 8414), dynamically registers OMA as a client (RFC 7591), and
 * runs authorization-code + PKCE against the discovered endpoints.
 *
 *   GET /v1/mcp/connectors/:connectorId/oauth/authorize?redirect_after=…
 *       Discover + register (cached after first call), generate state +
 *       PKCE verifier, persist them in oauth_states, return the
 *       authorize URL the UI should send the user to.
 *
 *   GET /v1/mcp/connectors/:connectorId/oauth/callback?code=&state=
 *       Look up state, exchange code at the discovered token endpoint,
 *       encrypt + store tokens, redirect the user back to redirect_after
 *       with ?oauth_success=1 or ?oauth_error=… .
 */

import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { getDB, newId } from "../db/index.js";
import { encrypt } from "../lib/encryption.js";
import { currentUser } from "../lib/current-user.js";
import { auditLog } from "./governance.js";
import { CONNECTORS } from "./mcp-discovery.js";
import {
  buildCallbackUrl,
  generateState,
  generatePKCE,
} from "../lib/oauth.js";
import {
  getOrCreateOAuthClient,
  buildDiscoveredAuthorizeUrl,
  exchangeCodeAtDiscoveredEndpoint,
  loadCachedClient,
  OAuthDiscoveryError,
} from "../lib/mcp-oauth-discovery.js";

const tags = ["MCP OAuth"];

const STATE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_UI_REDIRECT = "/quickstart";

// ── Schemas ────────────────────────────────────────────────────────────────

const AuthorizeQuerySchema = z.object({
  redirect_after: z.string().optional(),
});

const AuthorizeResponseSchema = z.object({
  authorize_url: z.string(),
  state: z.string(),
});

const CallbackQuerySchema = z.object({
  code: z.string().optional(),
  state: z.string().optional(),
  error: z.string().optional(),
  error_description: z.string().optional(),
});

// ── Routes ─────────────────────────────────────────────────────────────────

const authorizeRoute = createRoute({
  method: "get",
  path: "/v1/mcp/connectors/{connectorId}/oauth/authorize",
  tags,
  summary:
    "Begin the OAuth dance for an MCP connector. Discovers + registers with the MCP server's OAuth provider (RFC 8414 + 7591), then returns the authorize URL.",
  request: {
    params: z.object({ connectorId: z.string() }),
    query: AuthorizeQuerySchema,
  },
  responses: {
    200: {
      description: "Authorize URL ready",
      content: { "application/json": { schema: AuthorizeResponseSchema } },
    },
    400: {
      description: "Connector is not an OAuth connector",
      content: {
        "application/json": {
          schema: z.object({
            error: z.object({ type: z.string(), message: z.string() }),
          }),
        },
      },
    },
    404: {
      description: "Unknown connector",
      content: {
        "application/json": {
          schema: z.object({
            error: z.object({ type: z.string(), message: z.string() }),
          }),
        },
      },
    },
    503: {
      description: "OAuth discovery or registration failed for this MCP server",
      content: {
        "application/json": {
          schema: z.object({
            error: z.object({ type: z.string(), message: z.string() }),
          }),
        },
      },
    },
  },
});

const callbackRoute = createRoute({
  method: "get",
  path: "/v1/mcp/connectors/{connectorId}/oauth/callback",
  tags,
  summary:
    "Receive the MCP server's OAuth callback, exchange code for tokens, persist the connection.",
  request: {
    params: z.object({ connectorId: z.string() }),
    query: CallbackQuerySchema,
  },
  responses: {
    302: { description: "Redirect back to the UI (success or error toast)" },
  },
});

// ── Implementation ─────────────────────────────────────────────────────────

async function gcExpiredStates(now: string): Promise<void> {
  const db = await getDB();
  try {
    await db.run("DELETE FROM oauth_states WHERE expires_at < ?", now);
  } catch {
    // Non-fatal — failing to GC just leaves a few rows around.
  }
}

export function registerMCPOAuthRoutes(app: OpenAPIHono) {
  app.openapi(authorizeRoute, async (c) => {
    const { connectorId } = c.req.valid("param");
    const { redirect_after } = c.req.valid("query");

    const connector = CONNECTORS.find((r) => r.id === connectorId);
    if (!connector) {
      return c.json(
        {
          error: {
            type: "not_found",
            message: `Connector ${connectorId} not found`,
          },
        },
        404,
      );
    }
    if (connector.auth_type !== "oauth") {
      return c.json(
        {
          error: {
            type: "not_an_oauth_connector",
            message: `Connector ${connectorId} uses ${connector.auth_type} auth, not OAuth`,
          },
        },
        400,
      );
    }

    const user = await currentUser(c);
    const organizationId = user?.organization_id ?? "org_default";

    const now = new Date();
    const nowIso = now.toISOString();
    await gcExpiredStates(nowIso);

    const redirectUri = buildCallbackUrl(connectorId);
    const clientName = `Open Managed Agents (${organizationId})`;

    let oauthClient;
    try {
      oauthClient = await getOrCreateOAuthClient({
        organizationId,
        connectorId,
        mcpServerUrl: connector.url,
        redirectUri,
        clientName,
      });
    } catch (err) {
      const msg =
        err instanceof OAuthDiscoveryError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err);
      return c.json(
        {
          error: {
            type: "oauth_discovery_failed",
            message: msg,
          },
        },
        503,
      );
    }

    // Generate state. PKCE is required for public clients
    // (clientSecret = undefined); recommended otherwise.
    const state = generateState();
    const pkce = generatePKCE();
    const expiresAt = new Date(now.getTime() + STATE_TTL_MS).toISOString();

    const db = await getDB();
    await db.run(
      `INSERT INTO oauth_states (state, connector_id, organization_id, user_id, code_verifier, redirect_after, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      state,
      connectorId,
      organizationId,
      user?.id ?? null,
      pkce.verifier,
      redirect_after ?? DEFAULT_UI_REDIRECT,
      nowIso,
      expiresAt,
    );

    const authorizeUrl = buildDiscoveredAuthorizeUrl({
      authorizationEndpoint: oauthClient.authorizationEndpoint,
      clientId: oauthClient.clientId,
      redirectUri,
      state,
      codeChallenge: pkce.challenge,
    });

    return c.json({ authorize_url: authorizeUrl, state }, 200);
  });

  app.openapi(callbackRoute, async (c) => {
    const { connectorId } = c.req.valid("param");
    const { code, state, error, error_description } = c.req.valid("query");

    const fail = (errType: string, msg: string, fallback = DEFAULT_UI_REDIRECT) => {
      const params = new URLSearchParams({
        oauth_error: errType,
        oauth_error_message: msg.slice(0, 200),
        oauth_connector: connectorId,
      });
      return c.redirect(`${fallback}?${params.toString()}`, 302);
    };

    if (error) {
      return fail(
        error,
        error_description ?? `${connectorId} declined the authorization request`,
      );
    }
    if (!code || !state) {
      return fail("missing_params", "OAuth callback missing code or state");
    }

    const db = await getDB();
    const stateRow = await db.get<{
      connector_id: string;
      organization_id: string;
      user_id: string | null;
      code_verifier: string | null;
      redirect_after: string | null;
      expires_at: string;
    }>(
      "SELECT connector_id, organization_id, user_id, code_verifier, redirect_after, expires_at FROM oauth_states WHERE state = ?",
      state,
    );
    if (!stateRow) {
      return fail("invalid_state", "OAuth state not found or already consumed");
    }
    // Consume immediately to reject replays.
    await db.run("DELETE FROM oauth_states WHERE state = ?", state);

    const fallbackUi = stateRow.redirect_after ?? DEFAULT_UI_REDIRECT;
    if (stateRow.expires_at < new Date().toISOString()) {
      return fail(
        "state_expired",
        "OAuth handshake took too long — try again",
        fallbackUi,
      );
    }
    if (stateRow.connector_id !== connectorId) {
      return fail(
        "connector_mismatch",
        "OAuth state was for a different connector",
        fallbackUi,
      );
    }

    const cached = await loadCachedClient(stateRow.organization_id, connectorId);
    if (!cached) {
      return fail(
        "client_not_registered",
        "No registered OAuth client found — re-initiate the connect flow",
        fallbackUi,
      );
    }

    const redirectUri = buildCallbackUrl(connectorId);

    let exchangeResult;
    try {
      exchangeResult = await exchangeCodeAtDiscoveredEndpoint({
        tokenEndpoint: cached.tokenEndpoint,
        client: cached,
        code,
        redirectUri,
        codeVerifier: stateRow.code_verifier ?? undefined,
      });
    } catch (err) {
      const msg =
        err instanceof OAuthDiscoveryError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err);
      return fail("token_exchange_failed", msg, fallbackUi);
    }

    // Upsert the connection — same pattern as the legacy /connect route.
    await db.run(
      "DELETE FROM mcp_connections WHERE organization_id = ? AND connector_id = ?",
      stateRow.organization_id,
      connectorId,
    );
    await db.run(
      `INSERT INTO mcp_connections
       (id, organization_id, connector_id, auth_type, token_encrypted, refresh_token_encrypted, expires_at, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      newId("mcpconn"),
      stateRow.organization_id,
      connectorId,
      "oauth",
      encrypt(exchangeResult.accessToken),
      exchangeResult.refreshToken ? encrypt(exchangeResult.refreshToken) : null,
      exchangeResult.expiresAt ?? null,
      stateRow.user_id,
    );

    await auditLog(
      stateRow.user_id,
      "connect",
      "mcp_connector",
      connectorId,
      JSON.stringify({ auth_type: "oauth", method: "discovery+pkce" }),
    );

    const successParams = new URLSearchParams({
      oauth_success: "1",
      oauth_connector: connectorId,
    });
    return c.redirect(`${fallbackUi}?${successParams.toString()}`, 302);
  });
}
