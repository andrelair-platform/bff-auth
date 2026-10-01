# @andrelair-platform/bff-auth

[![CI](https://github.com/andrelair-platform/bff-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/andrelair-platform/bff-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue)](https://www.typescriptlang.org/)

> A tiny, framework-agnostic OAuth2 **client-credentials** token provider for server-side BFFs that call
> JWKS-protected backends on the minicloud / ktayl-solution platform. It mints a scoped Authentik bearer
> token server-side and caches it in memory until shortly before expiry — mirroring the backend-side
> pattern so both ends of a service call share one mental model.

**Why:** a Next.js (or any Node) BFF calling a backend that validates Authentik JWTs must present a
scoped bearer. Rather than reimplement the client-credentials grant + caching in every app, consume this.
First consumer: `ktayl-underwriting` (the workbench BFF → the JWKS-protected underwriting backend).

## Install

This package publishes to **GitHub Packages**. Add an `.npmrc` to the consuming repo:

```
@andrelair-platform:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

```bash
npm install @andrelair-platform/bff-auth
```

## Usage

```ts
import { tokenProviderFromEnv } from "@andrelair-platform/bff-auth";

// Reads OIDC_TOKEN_URL / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_SCOPE from env.
// Returns null when unset (dev / auth-off) → send no Authorization header.
const getApiToken = tokenProviderFromEnv();

async function authHeaders(): Promise<Record<string, string>> {
  const token = await getApiToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
```

Or configure explicitly (e.g. multiple audiences):

```ts
import { createClientCredentialsTokenProvider } from "@andrelair-platform/bff-auth";

const getToken = createClientCredentialsTokenProvider({
  tokenUrl: "http://authentik-server.authentik.svc/application/o/token/",
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  scope: "underwriting:read underwriting:write",
});
```

## API

| Export | Purpose |
|---|---|
| `createClientCredentialsTokenProvider(config \| null, options?)` | A provider with its **own** cache. `null` config → always resolves `null` (auth off). |
| `tokenProviderFromEnv(prefix?, options?)` | Convenience provider configured from env (null if any key missing). |
| `clientCredentialsConfigFromEnv(prefix?, env?)` | Build a config object from env, or `null`. |

**Options:** `expirySkewMs` (default 30s), `defaultTtlMs` (default 300s), `fetchImpl` + `now` (injectable for tests).

Each provider caches its token until `expiry − skew`. `fetch` must be available (Node 18+ / edge / browser).

## License

MIT
