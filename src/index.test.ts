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

function okResponse(accessToken: string, expiresIn?: number) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ access_token: accessToken, ...(expiresIn != null ? { expires_in: expiresIn } : {}) }),
  } as unknown as Response;
}

describe("createClientCredentialsTokenProvider", () => {
  it("returns null for a null config (auth off / dev) and never fetches", async () => {
    const fetchImpl = vi.fn();
    const provider = createClientCredentialsTokenProvider(null, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).resolves.toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("mints a client-credentials token with the configured grant + scope", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse("tok-1", 300));
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).resolves.toBe("tok-1");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(CFG.tokenUrl);
    const body = (init as RequestInit).body as URLSearchParams;
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("client_id")).toBe("cid");
    expect(body.get("scope")).toBe("underwriting:read underwriting:write");
  });

  it("caches per-instance until shortly before expiry", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse("cached", 300));
    const now = vi.fn<() => number>().mockReturnValue(0);
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch, now });
    await provider();
    now.mockReturnValue(100_000);
    await expect(provider()).resolves.toBe("cached");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("refreshes after expiry minus skew", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(okResponse("old", 300))
      .mockResolvedValueOnce(okResponse("new", 300));
    const now = vi.fn<() => number>().mockReturnValue(0);
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch, now });
    await expect(provider()).resolves.toBe("old");
    now.mockReturnValue(280_000);
    await expect(provider()).resolves.toBe("new");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("two providers keep independent caches", async () => {
    const f1 = vi.fn().mockResolvedValue(okResponse("a", 300));
    const f2 = vi.fn().mockResolvedValue(okResponse("b", 300));
    const p1 = createClientCredentialsTokenProvider(CFG, { fetchImpl: f1 as unknown as typeof fetch });
    const p2 = createClientCredentialsTokenProvider(CFG, { fetchImpl: f2 as unknown as typeof fetch });
    await expect(p1()).resolves.toBe("a");
    await expect(p2()).resolves.toBe("b");
  });

  it("throws on a non-OK token endpoint response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({ ok: false, status: 401 } as unknown as Response);
    const provider = createClientCredentialsTokenProvider(CFG, { fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(provider()).rejects.toThrow(/401/);
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
