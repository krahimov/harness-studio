/**
 * OAuth 2.0 Authorization Code (+ PKCE) helpers for MCP connectors.
 *
 * Architecture:
 *   - Each connector that uses OAuth has a static config block in
 *     OAUTH_PROVIDERS (authorize URL, token URL, quirks per provider).
 *   - Client credentials (client_id + client_secret) live in env vars
 *     by convention: `<CONNECTOR_ID>_OAUTH_CLIENT_ID` and
 *     `<CONNECTOR_ID>_OAUTH_CLIENT_SECRET`. Each self-hosted OMA
 *     install registers its own OAuth app with each provider and
 *     pastes the credentials into its .env. Documented in .env.example.
 *   - Callback URL is a fixed pattern: `<BASE>/v1/mcp/connectors/:id/oauth/callback`
 *     where BASE = `OAUTH_CALLBACK_BASE_URL` env var (defaults to
 *     `http://localhost:3001` for dev). Admins register that exact URL
 *     against their provider apps.
 *
 * The handshake is the standard:
 *   1. /oauth/authorize generates state + (optional) PKCE verifier,
 *      stores them in `oauth_states`, then 302-redirects to the
 *      provider's authorize URL.
 *   2. Provider redirects back to /oauth/callback?code=&state=.
 *   3. We look up state, verify, exchange the code for a token at
 *      the provider's token endpoint, encrypt + store in
 *      `mcp_connections`, delete the state row, redirect the user
 *      back to the UI.
 *
 * Refresh-token + expiry handling is plumbed (columns exist, exchange
 * captures them) but the active refresh in loadConnectorToken is a
 * follow-up — Notion (first vertical slice) doesn't expire tokens.
 */

import { randomBytes, createHash } from "node:crypto";

// ── Provider registry ──────────────────────────────────────────────────────

export type TokenRequestFormat = "form" | "json";

export interface OAuthProvider {
  /** Authorization endpoint the browser is redirected to. */
  authorizeUrl: string;
  /** Token endpoint the server POSTs to with the auth code. */
  tokenUrl: string;
  /**
   * How client_id + client_secret are sent to the token endpoint.
   * - "basic": HTTP Basic Authorization header (Notion, GitHub)
   * - "body": included in the POST body (Slack default)
   */
  clientAuthMethod: "basic" | "body";
  /**
   * Body format for the token endpoint.
   * - "form": application/x-www-form-urlencoded (OAuth 2.0 spec default)
   * - "json": application/json (Notion uses this)
   */
  tokenRequestFormat: TokenRequestFormat;
  /** Default scopes to request. User-overridable per connect. */
  defaultScopes?: string[];
  /**
   * Extra query params appended to the authorize URL. e.g. Notion
   * requires `owner=user`.
   */
  additionalAuthorizeParams?: Record<string, string>;
  /**
   * Extra headers sent to the token endpoint. e.g. Notion requires
   * Notion-Version.
   */
  additionalTokenHeaders?: Record<string, string>;
  /**
   * If true, request a refresh token at authorize time. Not all
   * providers honor this — see provider docs.
   */
  refreshSupported: boolean;
  /** PKCE Authorization Code flow. Recommended for all new integrations. */
  pkce: boolean;
}

export const OAUTH_PROVIDERS: Record<string, OAuthProvider> = {
  notion: {
    authorizeUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    clientAuthMethod: "basic",
    tokenRequestFormat: "json",
    additionalAuthorizeParams: { owner: "user" },
    additionalTokenHeaders: { "Notion-Version": "2022-06-28" },
    refreshSupported: false,
    pkce: false,
  },
  // Future providers (slack, linear, asana, ...) plug in here with
  // their endpoint URLs and quirks. Each one also needs its own
  // <CONNECTOR>_OAUTH_CLIENT_ID/SECRET env vars at runtime.
};

// ── Client credentials lookup ──────────────────────────────────────────────

export interface OAuthClientCredentials {
  clientId: string;
  clientSecret: string;
}

export function getOAuthCredentials(
  connectorId: string,
): OAuthClientCredentials | null {
  const upper = connectorId.toUpperCase();
  const clientId = process.env[`${upper}_OAUTH_CLIENT_ID`];
  const clientSecret = process.env[`${upper}_OAUTH_CLIENT_SECRET`];
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export function getCallbackBaseUrl(): string {
  return process.env.OAUTH_CALLBACK_BASE_URL ?? "http://localhost:3001";
}

export function buildCallbackUrl(connectorId: string): string {
  return `${getCallbackBaseUrl()}/v1/mcp/connectors/${connectorId}/oauth/callback`;
}

// ── State + PKCE helpers ───────────────────────────────────────────────────

export function generateState(): string {
  return randomBytes(32).toString("base64url");
}

export interface PKCEPair {
  verifier: string;
  challenge: string;
}

export function generatePKCE(): PKCEPair {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

// ── Authorize URL ──────────────────────────────────────────────────────────

export function buildAuthorizeUrl(opts: {
  provider: OAuthProvider;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  scopes?: string[];
}): string {
  const url = new URL(opts.provider.authorizeUrl);
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", opts.state);

  const scopes = opts.scopes ?? opts.provider.defaultScopes;
  if (scopes && scopes.length > 0) {
    url.searchParams.set("scope", scopes.join(" "));
  }

  if (opts.provider.pkce && opts.codeChallenge) {
    url.searchParams.set("code_challenge", opts.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  if (opts.provider.additionalAuthorizeParams) {
    for (const [k, v] of Object.entries(opts.provider.additionalAuthorizeParams)) {
      url.searchParams.set(k, v);
    }
  }

  return url.toString();
}

// ── Token exchange ─────────────────────────────────────────────────────────

export interface TokenExchangeResult {
  accessToken: string;
  refreshToken?: string;
  /** ISO 8601 timestamp; undefined if the provider didn't return expires_in. */
  expiresAt?: string;
  /** Raw provider response — useful for provider-specific extras like workspace_id. */
  raw: Record<string, unknown>;
}

export class OAuthError extends Error {
  readonly status: number;
  readonly type: string;
  constructor(message: string, status = 502, type = "oauth_error") {
    super(message);
    this.status = status;
    this.type = type;
  }
}

export async function exchangeCodeForToken(opts: {
  provider: OAuthProvider;
  credentials: OAuthClientCredentials;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}): Promise<TokenExchangeResult> {
  return postToTokenEndpoint(opts.provider, opts.credentials, {
    grant_type: "authorization_code",
    code: opts.code,
    redirect_uri: opts.redirectUri,
    ...(opts.codeVerifier ? { code_verifier: opts.codeVerifier } : {}),
  });
}

export async function refreshAccessToken(opts: {
  provider: OAuthProvider;
  credentials: OAuthClientCredentials;
  refreshToken: string;
}): Promise<TokenExchangeResult> {
  if (!opts.provider.refreshSupported) {
    throw new OAuthError(
      "refresh not supported by this provider",
      400,
      "oauth_refresh_unsupported",
    );
  }
  return postToTokenEndpoint(opts.provider, opts.credentials, {
    grant_type: "refresh_token",
    refresh_token: opts.refreshToken,
  });
}

async function postToTokenEndpoint(
  provider: OAuthProvider,
  credentials: OAuthClientCredentials,
  bodyFields: Record<string, string>,
): Promise<TokenExchangeResult> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(provider.additionalTokenHeaders ?? {}),
  };

  let bodyPayload: Record<string, string> = { ...bodyFields };

  if (provider.clientAuthMethod === "basic") {
    const creds = Buffer.from(
      `${credentials.clientId}:${credentials.clientSecret}`,
    ).toString("base64");
    headers.Authorization = `Basic ${creds}`;
  } else {
    bodyPayload = {
      ...bodyPayload,
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
    };
  }

  let body: string;
  if (provider.tokenRequestFormat === "json") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(bodyPayload);
  } else {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(bodyPayload).toString();
  }

  let res: Response;
  try {
    res = await fetch(provider.tokenUrl, { method: "POST", headers, body });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthError(`token endpoint unreachable: ${msg}`, 502);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new OAuthError(
      `token exchange failed (${res.status}): ${text.slice(0, 400)}`,
      res.status === 401 ? 401 : 502,
      res.status === 401 ? "oauth_unauthorized" : "oauth_error",
    );
  }

  const raw = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const accessToken = typeof raw.access_token === "string" ? raw.access_token : "";
  if (!accessToken) {
    throw new OAuthError(
      "token endpoint returned no access_token",
      502,
      "oauth_missing_access_token",
    );
  }

  const refreshToken =
    typeof raw.refresh_token === "string" ? raw.refresh_token : undefined;
  const expiresIn =
    typeof raw.expires_in === "number" ? raw.expires_in : undefined;
  const expiresAt = expiresIn
    ? new Date(Date.now() + expiresIn * 1000).toISOString()
    : undefined;

  return { accessToken, refreshToken, expiresAt, raw };
}
