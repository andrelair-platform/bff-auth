// @andrelair-platform/bff-auth — a tiny OAuth2 client-credentials token provider for server-side BFFs
// that call JWKS-protected backends on the minicloud platform.
//
// A BFF (e.g. a Next.js server component / server action) must present a scoped bearer token to a
// backend that validates Authentik-issued JWTs. This mints that token via the client-credentials grant
// and caches it in memory until shortly before expiry.
//
// The OAuth2 grant itself is delegated to **openid-client** (panva) — the de-facto, spec-complete,
// zero-runtime-dependency OAuth2/OIDC client — rather than hand-rolled. This package adds only the thin
// platform convention on top: env-driven config, a per-instance cache, and "no config → null" so a BFF
// can wire it unconditionally and stay auth-off in dev.

import * as oidc from "openid-client";

/** OAuth2 client-credentials configuration for one token audience. */
export interface ClientCredentialsConfig {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  /** Space-delimited scopes, e.g. "underwriting:read underwriting:write". */
  scope: string;
}

export interface TokenProviderOptions {
  /** Refresh this long before actual expiry to avoid a race near expiry. Default 30s. */
  expirySkewMs?: number;
  /** Lifetime to assume when the token endpoint omits expires_in. Default 300s. */
  defaultTtlMs?: number;
  /** Injectable fetch (tests / non-global-fetch runtimes). Wired into openid-client. */
  fetchImpl?: typeof fetch;
  /** Injectable clock (tests). Default: Date.now. */
  now?: () => number;
  /**
   * Permit a plain-HTTP token endpoint. Defaults to true when the endpoint is `http:` (minicloud
   * internal services are cluster-HTTP behind NetworkPolicies); set false to force HTTPS-only.
   */
  allowInsecureHttp?: boolean;
}

/** A provider yields a bearer token string, or null when no config is present (auth-off / dev). */
export type TokenProvider = () => Promise<string | null>;

const DEFAULT_EXPIRY_SKEW_MS = 30_000;
const DEFAULT_TTL_MS = 300_000;

/** Access process.env without a hard Node type dependency (works on Node/edge/browser). */
function defaultEnv(): Record<string, string | undefined> {
  const g = globalThis as { process?: { env?: Record<string, string | undefined> } };
  return g.process?.env ?? {};
}

/**
 * Build a cached client-credentials token provider for one config.
 * Pass `null` config → the provider always resolves to `null` (auth disabled, e.g. dev).
 */
export function createClientCredentialsTokenProvider(
  config: ClientCredentialsConfig | null,
  options: TokenProviderOptions = {},
): TokenProvider {
  const skew = options.expirySkewMs ?? DEFAULT_EXPIRY_SKEW_MS;
  const defaultTtl = options.defaultTtlMs ?? DEFAULT_TTL_MS;
  const now = options.now ?? Date.now;

  // Build the openid-client Configuration once (no discovery — the token endpoint is explicit).
  let oidcConfig: oidc.Configuration | null = null;
  if (config) {
    const tokenUrl = new URL(config.tokenUrl);
    oidcConfig = new oidc.Configuration(
      { issuer: tokenUrl.origin, token_endpoint: config.tokenUrl },
      config.clientId,
      config.clientSecret,
      // Send credentials in the POST body (client_secret_post) — matches Authentik's confidential client.
      oidc.ClientSecretPost(config.clientSecret),
    );
    const allowHttp = options.allowInsecureHttp ?? tokenUrl.protocol === "http:";
    if (allowHttp) oidc.allowInsecureRequests(oidcConfig);
    if (options.fetchImpl) {
      (oidcConfig as unknown as Record<symbol, typeof fetch>)[oidc.customFetch] = options.fetchImpl;
    }
  }

  let cachedToken: string | null = null;
  let expiresAtMs = 0;

  return async function getToken(): Promise<string | null> {
    if (!config || !oidcConfig) return null;

    const t = now();
    if (cachedToken !== null && t < expiresAtMs - skew) {
      return cachedToken;
    }

    const tokens = await oidc.clientCredentialsGrant(oidcConfig, { scope: config.scope });
    cachedToken = tokens.access_token;
    const ttlMs = tokens.expires_in != null ? Number(tokens.expires_in) * 1000 : defaultTtl;
    expiresAtMs = t + ttlMs;
    return cachedToken;
  };
}

/**
 * Read client-credentials config from `process.env` using the standard key names
 * (`OIDC_TOKEN_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPE`), with an optional prefix
 * (e.g. prefix "UW_" → "UW_OIDC_TOKEN_URL"). Returns null if any key is missing (→ auth-off / dev).
 */
export function clientCredentialsConfigFromEnv(
  prefix = "",
  env: Record<string, string | undefined> = defaultEnv(),
): ClientCredentialsConfig | null {
  const tokenUrl = env[`${prefix}OIDC_TOKEN_URL`];
  const clientId = env[`${prefix}OIDC_CLIENT_ID`];
  const clientSecret = env[`${prefix}OIDC_CLIENT_SECRET`];
  const scope = env[`${prefix}OIDC_SCOPE`];
  if (!tokenUrl || !clientId || !clientSecret || !scope) return null;
  return { tokenUrl, clientId, clientSecret, scope };
}

/** Convenience: a provider configured from env (the common BFF case). Reads env ONCE at build time. */
export function tokenProviderFromEnv(prefix = "", options: TokenProviderOptions = {}): TokenProvider {
  return createClientCredentialsTokenProvider(clientCredentialsConfigFromEnv(prefix), options);
}
