// @andrelair-platform/bff-auth — a tiny, framework-agnostic OAuth2 client-credentials token provider
// for server-side BFFs that call JWKS-protected backends on the minicloud platform.
//
// A BFF (e.g. a Next.js server component / server action) must present a scoped bearer token to a
// backend that validates Authentik-issued JWTs. This mints that token via the client-credentials grant
// and caches it in memory until shortly before expiry. It mirrors the backend-side pattern
// (ktayl-underwriting app/bind/token.py) so both sides of a call share one mental model.
//
// Design: a FACTORY returns a provider with its OWN cache — so an app can hold several providers
// (different scopes/clients) without a shared module-global colliding. `fetchImpl`/`now` are injectable
// for tests. No framework or Node-API dependency beyond global `fetch` (Node 18+ / edge / browsers).

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
  /** Injectable fetch (tests / non-global-fetch runtimes). Default: global fetch. */
  fetchImpl?: typeof fetch;
  /** Injectable clock (tests). Default: Date.now. */
  now?: () => number;
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

interface TokenResponse {
  access_token: string;
  expires_in?: number;
}

/**
 * Build a cached client-credentials token provider for one config.
 * Pass `null` config → the provider always resolves to `null` (auth disabled, e.g. dev) so callers
 * can wire it unconditionally: `const h = token ? { Authorization: ` + "`Bearer ${token}`" + ` } : {}`.
 */
export function createClientCredentialsTokenProvider(
  config: ClientCredentialsConfig | null,
  options: TokenProviderOptions = {},
): TokenProvider {
  const skew = options.expirySkewMs ?? DEFAULT_EXPIRY_SKEW_MS;
  const defaultTtl = options.defaultTtlMs ?? DEFAULT_TTL_MS;
  const doFetch = options.fetchImpl ?? globalThis.fetch;
  const now = options.now ?? Date.now;

  let cachedToken: string | null = null;
  let expiresAtMs = 0;

  return async function getToken(): Promise<string | null> {
    if (!config) return null;

    const t = now();
    if (cachedToken !== null && t < expiresAtMs - skew) {
      return cachedToken;
    }
    if (typeof doFetch !== "function") {
      throw new Error("bff-auth: no fetch implementation available (pass options.fetchImpl)");
    }

    const res = await doFetch(config.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: config.scope,
      }),
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(`bff-auth: OIDC token endpoint returned ${res.status}`);
    }
    const body = (await res.json()) as TokenResponse;
    cachedToken = body.access_token;
    expiresAtMs = t + (body.expires_in != null ? body.expires_in * 1000 : defaultTtl);
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
