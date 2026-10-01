import { describe, expect, it, vi } from "vitest";

import {
  clientCredentialsConfigFromEnv,
  createClientCredentialsTokenProvider,
  tokenProviderFromEnv,
  type ClientCredentialsConfig,
} from "./index";

const CFG: ClientCredentialsConfig = {
  tokenUrl: "http://authentik.test/application/o/token/",
  clientId: "cid",
  clientSecret: "csec",
  scope: "underwriting:read underwriting:write",
};

// A standard OAuth2 token-endpoint success response (openid-client validates shape: access_token + token_type).
function tokenResponse(accessToken: string, expiresIn = 300): Response {
  return new Response(
    JSON.stringify({ access_token: accessToken, token_type: "Bearer", expires_in: expiresIn }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

describe("createClientCredentialsTokenProvider", () => {
  it("returns null for a null config (auth off / dev) and never calls the endpoint", async () => {
    const fetchImpl = vi.fn();
    const provider = createClientCredentialsTokenProvider(null, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).resolves.toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("mints a client-credentials token via openid-client (grant + scope in the body)", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(tokenResponse("tok-1"));
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).resolves.toBe("tok-1");

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe(CFG.tokenUrl);
    const body = String((init as RequestInit).body);
    expect(body).toContain("grant_type=client_credentials");
    expect(body).toContain("scope=underwriting");
  });

  it("caches per-instance until shortly before expiry (one grant call)", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(tokenResponse("cached", 300));
    const now = vi.fn<() => number>().mockReturnValue(0);
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch, now });
    await provider();
    now.mockReturnValue(100_000); // +100s, inside 300s - 30s skew
    await expect(provider()).resolves.toBe("cached");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("refreshes after expiry minus skew", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(tokenResponse("old", 300))
      .mockResolvedValueOnce(tokenResponse("new", 300));
    const now = vi.fn<() => number>().mockReturnValue(0);
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch, now });
    await expect(provider()).resolves.toBe("old");
    now.mockReturnValue(280_000); // past 300s - 30s skew → refresh
    await expect(provider()).resolves.toBe("new");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("two providers keep independent caches", async () => {
    const f1 = vi.fn().mockResolvedValue(tokenResponse("a"));
    const f2 = vi.fn().mockResolvedValue(tokenResponse("b"));
    const p1 = createClientCredentialsTokenProvider(CFG, { fetchImpl: f1 as unknown as typeof fetch });
    const p2 = createClientCredentialsTokenProvider(CFG, { fetchImpl: f2 as unknown as typeof fetch });
    await expect(p1()).resolves.toBe("a");
    await expect(p2()).resolves.toBe("b");
  });

  it("rejects on a token-endpoint error response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_client" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).rejects.toBeInstanceOf(Error);
  });
});

describe("clientCredentialsConfigFromEnv", () => {
  const full = {
    OIDC_TOKEN_URL: "u",
    OIDC_CLIENT_ID: "c",
    OIDC_CLIENT_SECRET: "s",
    OIDC_SCOPE: "sc",
  };

  it("builds config when all keys present", () => {
    expect(clientCredentialsConfigFromEnv("", full)).toEqual({ tokenUrl: "u", clientId: "c", clientSecret: "s", scope: "sc" });
  });

  it("returns null if any key is missing", () => {
    const { OIDC_SCOPE: _omit, ...partial } = full;
    expect(clientCredentialsConfigFromEnv("", partial)).toBeNull();
  });

  it("honours a prefix", () => {
    const prefixed = { UW_OIDC_TOKEN_URL: "u", UW_OIDC_CLIENT_ID: "c", UW_OIDC_CLIENT_SECRET: "s", UW_OIDC_SCOPE: "sc" };
    expect(clientCredentialsConfigFromEnv("UW_", prefixed)?.tokenUrl).toBe("u");
  });

  it("tokenProviderFromEnv with no config → null provider", async () => {
    const provider = tokenProviderFromEnv("MISSING_", {});
    await expect(provider()).resolves.toBeNull();
  });
});
