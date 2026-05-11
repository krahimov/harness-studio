/**
 * OAuth authorization-code routes for MCP connectors.
 *
 * Two endpoints per connector:
 *   GET /v1/mcp/connectors/:connectorId/oauth/authorize?redirect_after=...
 *       Generates state + (optional) PKCE, stores them in oauth_states,
 *       302-redirects to the provider's authorize URL.
 *
 *   GET /v1/mcp/connectors/:connectorId/oauth/callback?code=&state=
 *       Receives the provider redirect, validates state, exchanges code
 *       for tokens, encrypts + stores in mcp_connections, deletes the
 *       state row, redirects the user back to redirect_after (or a
 *       default success page).
 *
 * Errors on /authorize return a 4xx JSON to the caller. Errors on
 * /callback redirect back to the UI with ?oauth_error=… so the user
 * gets a visible toast instead of a raw 500.
 */

import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { getDB, newId } from "../db/index.js";
import { encrypt } from "../lib/encryption.js";
import { currentUser } from "../lib/current-user.js";
import { auditLog } from "./governance.js";
import { CONNECTORS } from "./mcp-discovery.js";
import {
  OAUTH_PROVIDERS,
  getOAuthCredentials,
  buildCallbackUrl,
  buildAuthorizeUrl,
  generateState,
  generatePKCE,
  exchangeCodeForToken,
  OAuthError,
} from "../lib/oauth.js";

const tags = ["MCP OAuth"];

const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const DEFAULT_UI_REDIRECT = "/quickstart";

// ── Schemas ────────────────────────────────────────────────────────────────

const AuthorizeQuerySchema = z.object({
  /** Optional UI path the user is sent back to on success. Defaults to /quickstart. */
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
    "Begin the OAuth authorization-code dance for an MCP connector. Returns the authorize URL the UI should open.",
  request: {
    params: z.object({ connectorId: z.string() }),
    query: AuthorizeQuerySchema,
  },
  responses: {
    200: {
      description: "Authorize URL ready",
      content: { "application/json": { schema: AuthorizeResponseSchema } },
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
      description: "OAuth client credentials not configured for this connector",
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
    "Receive the OAuth provider callback, exchange code for tokens, store the connection.",
  request: {
    params: z.object({ connectorId: z.string() }),
    query: CallbackQuerySchema,
  },
  responses: {
    302: {
      description: "Redirect back to the UI (success or error toast)",
    },
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

    const provider = OAUTH_PROVIDERS[connectorId];
    if (!provider) {
      return c.json(
        {
          error: {
            type: "oauth_not_supported",
            message: `Connector ${connectorId} is not configured for OAuth in this build`,
          },
        },
        503,
      );
    }

    const credentials = getOAuthCredentials(connectorId);
    if (!credentials) {
      const upper = connectorId.toUpperCase();
      return c.json(
        {
          error: {
            type: "oauth_credentials_missing",
            message: `Set ${upper}_OAUTH_CLIENT_ID and ${upper}_OAUTH_CLIENT_SECRET in the server env to enable ${connectorId} OAuth.`,
          },
        },
        503,
      );
    }

    const user = await currentUser(c);
    const organizationId = user?.organization_id ?? "org_default";

    const now = new Date();
    const nowIso = now.toISOString();
    await gcExpiredStates(nowIso);

    const state = generateState();
    const pkce = provider.pkce ? generatePKCE() : null;
    const expiresAt = new Date(now.getTime() + STATE_TTL_MS).toISOString();

    const db = await getDB();
    await db.run(
      `INSERT INTO oauth_states (state, connector_id, organization_id, user_id, code_verifier, redirect_after, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      state,
      connectorId,
      organizationId,
      user?.id ?? null,
      pkce?.verifier ?? null,
      redirect_after ?? DEFAULT_UI_REDIRECT,
      nowIso,
      expiresAt,
    );

    const redirectUri = buildCallbackUrl(connectorId);
    const authorizeUrl = buildAuthorizeUrl({
      provider,
      clientId: credentials.clientId,
      redirectUri,
      state,
      codeChallenge: pkce?.challenge,
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
      const url = `${fallback}?${params.toString()}`;
      return c.redirect(url, 302);
    };

    // 1. Provider returned an error in the redirect
    if (error) {
      return fail(
        error,
        error_description ?? `${connectorId} declined the authorization request`,
      );
    }
    if (!code || !state) {
      return fail("missing_params", "OAuth callback missing code or state");
    }

    const provider = OAUTH_PROVIDERS[connectorId];
    if (!provider) {
      return fail(
        "oauth_not_supported",
        `Connector ${connectorId} is not configured for OAuth in this build`,
      );
    }

    const credentials = getOAuthCredentials(connectorId);
    if (!credentials) {
      return fail(
        "oauth_credentials_missing",
        `Server env vars missing for ${connectorId}`,
      );
    }

    // 2. Look up + consume the state row
    const db = await getDB();
    const nowIso = new Date().toISOString();
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
      return fail(
        "invalid_state",
        "OAuth state not found or already consumed",
      );
    }
    // Consume the state immediately so a replay is rejected.
    await db.run("DELETE FROM oauth_states WHERE state = ?", state);

    if (stateRow.expires_at < nowIso) {
      return fail(
        "state_expired",
        "OAuth handshake took too long — try again",
        stateRow.redirect_after ?? DEFAULT_UI_REDIRECT,
      );
    }
    if (stateRow.connector_id !== connectorId) {
      return fail(
        "connector_mismatch",
        "OAuth state was for a different connector",
        stateRow.redirect_after ?? DEFAULT_UI_REDIRECT,
      );
    }

    // 3. Exchange the code for tokens
    const redirectUri = buildCallbackUrl(connectorId);
    let exchangeResult;
    try {
      exchangeResult = await exchangeCodeForToken({
        provider,
        credentials,
        code,
        redirectUri,
        codeVerifier: stateRow.code_verifier ?? undefined,
      });
    } catch (err) {
      const msg =
        err instanceof OAuthError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err);
      return fail(
        "token_exchange_failed",
        msg,
        stateRow.redirect_after ?? DEFAULT_UI_REDIRECT,
      );
    }

    // 4. UPSERT the connection — same pattern as /connect
    await db.run(
      "DELETE FROM mcp_connections WHERE organization_id = ? AND connector_id = ?",
      stateRow.organization_id,
      connectorId,
    );

    const connId = newId("mcpconn");
    await db.run(
      `INSERT INTO mcp_connections
       (id, organization_id, connector_id, auth_type, token_encrypted, refresh_token_encrypted, expires_at, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      connId,
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
      JSON.stringify({ auth_type: "oauth" }),
    );

    // 5. Redirect the user back to the UI with a success flag
    const successParams = new URLSearchParams({
      oauth_success: "1",
      oauth_connector: connectorId,
    });
    const dest = `${stateRow.redirect_after ?? DEFAULT_UI_REDIRECT}?${successParams.toString()}`;
    return c.redirect(dest, 302);
  });
}
