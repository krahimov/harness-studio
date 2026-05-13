/**
 * MCP-spec OAuth discovery + Dynamic Client Registration.
 *
 * Anthropic Managed Agents, Claude Desktop, Claude Code, Cursor, etc.
 * all connect to remote MCP servers like https://mcp.notion.com/mcp
 * without users needing to register an OAuth app upfront. They do this
 * by following the MCP authorization profile:
 *
 *   1. Probe `<server-origin>/.well-known/oauth-authorization-server`
 *      (RFC 8414) to discover authorize_endpoint, token_endpoint,
 *      registration_endpoint, supported grant types, PKCE methods, etc.
 *   2. POST to the registration_endpoint (RFC 7591 — Dynamic Client
 *      Registration) with our client metadata (client_name, redirect
 *      URIs, token_endpoint_auth_method). The server returns a
 *      freshly-minted client_id (and optionally client_secret).
 *   3. Run the standard authorize-code + PKCE flow against the
 *      discovered endpoints.
 *
 * This module covers steps 1 and 2; the route layer handles step 3 by
 * reusing the existing oauth.ts URL builder + code-exchange helpers.
 *
 * Cache: we register once per (organization, connector_id) and store
 * the result in mcp_oauth_clients so repeated Connect clicks don't
 * spam the provider's /register endpoint.
 */

import { getDB, newId } from "../db/index.js";
import { encrypt, decrypt } from "./encryption.js";

// ── Discovered metadata ────────────────────────────────────────────────────

export interface DiscoveredOAuthMetadata {
  /** Where the user is redirected to consent. */
  authorizationEndpoint: string;
  /** Where the server exchanges the code for a token. */
  tokenEndpoint: string;
  /** Where to register a new client (RFC 7591). undefined if the server doesn't support dynamic registration. */
  registrationEndpoint?: string;
  /** Whether the server supports PKCE S256. We prefer it when available. */
  pkceSupported: boolean;
  /** Auth methods the token endpoint accepts ("none", "client_secret_basic", "client_secret_post"). */
  tokenAuthMethods: string[];
}

export class OAuthDiscoveryError extends Error {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Probe `<origin>/.well-known/oauth-authorization-server` and return
 * the metadata fields we care about. Throws OAuthDiscoveryError if
 * the document isn't found or isn't shaped like RFC 8414.
 */
export async function discoverOAuthServer(
  mcpServerUrl: string,
): Promise<DiscoveredOAuthMetadata> {
  const origin = new URL(mcpServerUrl).origin;
  const discoveryUrl = `${origin}/.well-known/oauth-authorization-server`;

  let res: Response;
  try {
    res = await fetch(discoveryUrl, { headers: { Accept: "application/json" } });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthDiscoveryError(
      `OAuth discovery at ${discoveryUrl} unreachable: ${msg}`,
    );
  }
  if (!res.ok) {
    throw new OAuthDiscoveryError(
      `OAuth discovery at ${discoveryUrl} returned ${res.status}`,
    );
  }
  const doc = (await res.json().catch(() => ({}))) as Record<string, unknown>;

  const authorizationEndpoint = typeof doc.authorization_endpoint === "string"
    ? doc.authorization_endpoint
    : null;
  const tokenEndpoint = typeof doc.token_endpoint === "string"
    ? doc.token_endpoint
    : null;
  if (!authorizationEndpoint || !tokenEndpoint) {
    throw new OAuthDiscoveryError(
      "OAuth discovery document missing authorization_endpoint or token_endpoint",
    );
  }

  const registrationEndpoint = typeof doc.registration_endpoint === "string"
    ? doc.registration_endpoint
    : undefined;

  const pkceMethods = Array.isArray(doc.code_challenge_methods_supported)
    ? (doc.code_challenge_methods_supported as unknown[])
    : [];
  const pkceSupported = pkceMethods.includes("S256");

  const tokenAuthMethods = Array.isArray(doc.token_endpoint_auth_methods_supported)
    ? (doc.token_endpoint_auth_methods_supported as unknown[]).filter(
        (m): m is string => typeof m === "string",
      )
    : [];

  return {
    authorizationEndpoint,
    tokenEndpoint,
    registrationEndpoint,
    pkceSupported,
    tokenAuthMethods,
  };
}

// ── Dynamic Client Registration (RFC 7591) ─────────────────────────────────

export interface RegisteredClient {
  clientId: string;
  /** undefined for public clients (token_endpoint_auth_method = "none" + PKCE). */
  clientSecret?: string;
}

/**
 * Register OMA as a client at the MCP server's registration endpoint.
 * Returns the issued client_id (and optional client_secret).
 *
 * preferredAuthMethod: which token_endpoint_auth_method to request.
 * We pass the most secure one supported by the server (favouring
 * "none" + PKCE — public clients are simpler and avoid storing
 * yet-another secret).
 */
export async function registerOAuthClient(opts: {
  registrationEndpoint: string;
  redirectUri: string;
  clientName: string;
  preferredAuthMethod: string;
}): Promise<RegisteredClient> {
  const body = {
    client_name: opts.clientName,
    redirect_uris: [opts.redirectUri],
    token_endpoint_auth_method: opts.preferredAuthMethod,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };

  let res: Response;
  try {
    res = await fetch(opts.registrationEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthDiscoveryError(
      `Dynamic registration at ${opts.registrationEndpoint} unreachable: ${msg}`,
    );
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new OAuthDiscoveryError(
      `Dynamic registration failed (${res.status}): ${text.slice(0, 300)}`,
    );
  }
  const doc = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const clientId = typeof doc.client_id === "string" ? doc.client_id : null;
  if (!clientId) {
    throw new OAuthDiscoveryError(
      "Registration response missing client_id",
    );
  }
  const clientSecret = typeof doc.client_secret === "string"
    ? doc.client_secret
    : undefined;
  return { clientId, clientSecret };
}

/**
 * Pick the most secure auth method the server supports. We prefer
 * "none" (public client + PKCE) since it sidesteps storing yet
 * another secret. Fall back to "client_secret_basic" or
 * "client_secret_post" if those are the only options.
 */
export function pickAuthMethod(supported: string[]): string {
  if (supported.includes("none")) return "none";
  if (supported.includes("client_secret_basic")) return "client_secret_basic";
  if (supported.includes("client_secret_post")) return "client_secret_post";
  // Default fall-through — most servers accept basic.
  return "client_secret_basic";
}

// ── Persistence: cached client per (org, connector) ────────────────────────

export interface CachedClient {
  clientId: string;
  clientSecret?: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
}

export async function loadCachedClient(
  organizationId: string,
  connectorId: string,
): Promise<CachedClient | null> {
  const db = await getDB();
  const row = await db.get<{
    client_id: string;
    client_secret_encrypted: string | null;
    authorization_endpoint: string;
    token_endpoint: string;
    registration_endpoint: string | null;
  }>(
    "SELECT client_id, client_secret_encrypted, authorization_endpoint, token_endpoint, registration_endpoint FROM mcp_oauth_clients WHERE organization_id = ? AND connector_id = ?",
    organizationId,
    connectorId,
  );
  if (!row) return null;
  let clientSecret: string | undefined;
  if (row.client_secret_encrypted) {
    try {
      clientSecret = decrypt(row.client_secret_encrypted);
    } catch {
      // Encrypted blob is broken; treat as if we have no secret.
    }
  }
  return {
    clientId: row.client_id,
    clientSecret,
    authorizationEndpoint: row.authorization_endpoint,
    tokenEndpoint: row.token_endpoint,
    registrationEndpoint: row.registration_endpoint ?? undefined,
  };
}

export async function saveCachedClient(opts: {
  organizationId: string;
  connectorId: string;
  client: RegisteredClient;
  metadata: DiscoveredOAuthMetadata;
}): Promise<void> {
  const db = await getDB();
  // Upsert: delete any existing row for (org, connector), then insert.
  await db.run(
    "DELETE FROM mcp_oauth_clients WHERE organization_id = ? AND connector_id = ?",
    opts.organizationId,
    opts.connectorId,
  );
  await db.run(
    `INSERT INTO mcp_oauth_clients
     (id, organization_id, connector_id, client_id, client_secret_encrypted, authorization_endpoint, token_endpoint, registration_endpoint)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    newId("mcpoauth"),
    opts.organizationId,
    opts.connectorId,
    opts.client.clientId,
    opts.client.clientSecret ? encrypt(opts.client.clientSecret) : null,
    opts.metadata.authorizationEndpoint,
    opts.metadata.tokenEndpoint,
    opts.metadata.registrationEndpoint ?? null,
  );
}

/**
 * Cache lookup + (on miss) discover + register + cache. Returns
 * everything the routes need to run the OAuth dance.
 */
export async function getOrCreateOAuthClient(opts: {
  organizationId: string;
  connectorId: string;
  mcpServerUrl: string;
  redirectUri: string;
  clientName: string;
}): Promise<CachedClient & { pkceSupported: boolean }> {
  const cached = await loadCachedClient(opts.organizationId, opts.connectorId);
  if (cached) {
    // Re-probe pkce support cheaply by checking which methods the
    // token endpoint supports. We didn't persist that field, so
    // assume true (PKCE-capable servers are the common case) and
    // let the actual flow fail loudly if the server rejects it.
    return { ...cached, pkceSupported: true };
  }

  const metadata = await discoverOAuthServer(opts.mcpServerUrl);
  if (!metadata.registrationEndpoint) {
    throw new OAuthDiscoveryError(
      `MCP server ${opts.mcpServerUrl} does not advertise a registration_endpoint — cannot register dynamically. Pre-registered OAuth apps need to be wired via the legacy OAUTH_PROVIDERS path.`,
    );
  }

  const authMethod = pickAuthMethod(metadata.tokenAuthMethods);
  const client = await registerOAuthClient({
    registrationEndpoint: metadata.registrationEndpoint,
    redirectUri: opts.redirectUri,
    clientName: opts.clientName,
    preferredAuthMethod: authMethod,
  });

  await saveCachedClient({
    organizationId: opts.organizationId,
    connectorId: opts.connectorId,
    client,
    metadata,
  });

  return {
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    authorizationEndpoint: metadata.authorizationEndpoint,
    tokenEndpoint: metadata.tokenEndpoint,
    registrationEndpoint: metadata.registrationEndpoint,
    pkceSupported: metadata.pkceSupported,
  };
}

// ── Authorize URL + token exchange (using discovered endpoints) ────────────

export interface DiscoveredTokenResult {
  accessToken: string;
  refreshToken?: string;
  /** ISO 8601 timestamp; undefined if the server didn't return expires_in. */
  expiresAt?: string;
  /** Raw provider response — useful for server-specific extras (workspace_id, owner, etc.). */
  raw: Record<string, unknown>;
}

export function buildDiscoveredAuthorizeUrl(opts: {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  scopes?: string[];
  additionalParams?: Record<string, string>;
}): string {
  const url = new URL(opts.authorizationEndpoint);
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", opts.state);
  if (opts.codeChallenge) {
    url.searchParams.set("code_challenge", opts.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
  }
  if (opts.scopes?.length) {
    url.searchParams.set("scope", opts.scopes.join(" "));
  }
  if (opts.additionalParams) {
    for (const [k, v] of Object.entries(opts.additionalParams)) {
      url.searchParams.set(k, v);
    }
  }
  return url.toString();
}

/**
 * Exchange the authorization code at the (discovered) token endpoint.
 *
 * Auth method is inferred from the cached client:
 *   - `clientSecret` present  → confidential client; HTTP Basic auth
 *   - `clientSecret` undefined → public client; client_id in body, PKCE required
 */
export async function exchangeCodeAtDiscoveredEndpoint(opts: {
  tokenEndpoint: string;
  client: CachedClient;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}): Promise<DiscoveredTokenResult> {
  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", opts.code);
  params.set("redirect_uri", opts.redirectUri);
  if (opts.codeVerifier) params.set("code_verifier", opts.codeVerifier);

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };

  if (opts.client.clientSecret) {
    const creds = Buffer.from(
      `${opts.client.clientId}:${opts.client.clientSecret}`,
    ).toString("base64");
    headers.Authorization = `Basic ${creds}`;
  } else {
    // Public client: client_id in body, no secret (PKCE protects).
    params.set("client_id", opts.client.clientId);
  }

  let res: Response;
  try {
    res = await fetch(opts.tokenEndpoint, {
      method: "POST",
      headers,
      body: params.toString(),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthDiscoveryError(
      `Token endpoint ${opts.tokenEndpoint} unreachable: ${msg}`,
    );
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new OAuthDiscoveryError(
      `Token exchange failed (${res.status}): ${text.slice(0, 400)}`,
    );
  }

  const raw = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const accessToken = typeof raw.access_token === "string" ? raw.access_token : "";
  if (!accessToken) {
    throw new OAuthDiscoveryError(
      "Token endpoint returned no access_token",
    );
  }
  const refreshToken = typeof raw.refresh_token === "string"
    ? raw.refresh_token
    : undefined;
  const expiresIn = typeof raw.expires_in === "number" ? raw.expires_in : undefined;
  const expiresAt = expiresIn
    ? new Date(Date.now() + expiresIn * 1000).toISOString()
    : undefined;
  return { accessToken, refreshToken, expiresAt, raw };
}
