import { DurableObject } from "cloudflare:workers";
const encoder = new TextEncoder();
const supportedScopes = /* @__PURE__ */ new Set(["openid", "email", "profile"]);
class IdentityBrokerAuthStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }
  async putState(key, state) {
    await this.putExpiring(`state:${key}`, state, 600);
  }
  async consumeState(key) {
    return this.consume(`state:${key}`);
  }
  async putCode(key, record) {
    await this.putExpiring(`code:${key}`, record, 300);
  }
  async consumeCode(key) {
    return this.consume(`code:${key}`);
  }
  async putAccessToken(key, profile) {
    await this.putExpiring(`access:${key}`, profile, 900);
  }
  async getAccessToken(key) {
    const storageKey = `access:${key}`;
    const record = await this.ctx.storage.get(storageKey) ?? null;
    if (record == null) return null;
    if (record.expiresAt <= Date.now()) {
      await this.ctx.storage.delete(storageKey);
      return null;
    }
    return record.value;
  }
  async rateLimit(key, limit, periodSeconds) {
    const bucket = Math.floor(Date.now() / 1e3 / periodSeconds);
    const storageKey = `rate:${key}:${periodSeconds}:${bucket}`;
    const record = await this.ctx.storage.get(storageKey) ?? null;
    const count = record != null && record.expiresAt > Date.now() ? record.value : 0;
    if (count >= limit) return false;
    await this.putExpiring(storageKey, count + 1, periodSeconds * 2);
    return true;
  }
  async putExpiring(key, value, ttlSeconds) {
    await this.ctx.storage.put(key, { value, expiresAt: Date.now() + ttlSeconds * 1e3 });
  }
  async consume(key) {
    return this.ctx.storage.transaction(async (txn) => {
      const record = await txn.get(key) ?? null;
      if (record != null) await txn.delete(key);
      if (record == null || record.expiresAt <= Date.now()) return null;
      return record.value;
    });
  }
}
var index_default = {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/") {
        return home(env);
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true });
      }
      if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
        return openidConfiguration(env);
      }
      if (request.method === "GET" && url.pathname === "/jwks.json") {
        return jwks(env);
      }
      if (request.method === "GET" && url.pathname === "/authorize") {
        const limited = await enforceRateLimit(request, env, "authorize", 20, 60);
        if (limited != null) return limited;
        return authorize(request, env);
      }
      if (request.method === "GET" && url.pathname === "/callback/github") {
        const limited = await enforceRateLimit(request, env, "callback", 20, 60);
        if (limited != null) return limited;
        return oauthCallback(request, env, "github");
      }
      if (request.method === "GET" && url.pathname === "/callback/discord") {
        const limited = await enforceRateLimit(request, env, "callback", 20, 60);
        if (limited != null) return limited;
        return oauthCallback(request, env, "discord");
      }
      if (request.method === "POST" && url.pathname === "/token") {
        const limited = await enforceRateLimit(request, env, "token", 30, 60);
        if (limited != null) return limited;
        return token(request, env);
      }
      if (request.method === "GET" && url.pathname === "/userinfo") {
        const limited = await enforceRateLimit(request, env, "userinfo", 60, 60);
        if (limited != null) return limited;
        return userinfo(request, env);
      }
      return json({ error: "not_found" }, 404);
    } catch (error) {
      const errorId = randomString().slice(0, 12);
      console.error(`identity broker error ${errorId}`, errorMessage(error));
      return json({ error: "server_error", error_id: errorId }, 500);
    }
  }
};
function openidConfiguration(env) {
  const issuer = normalizedIssuer(env);
  return json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    scopes_supported: ["openid", "email", "profile"],
    claims_supported: [
      "sub",
      "email",
      "email_verified",
      "name",
      "preferred_username",
      "provider",
      "github_id",
      "github_login",
      "discord_id",
      "discord_username",
      "zt_principals"
    ]
  });
}
function jwks(env) {
  const jwk = privateJwk(env);
  const publicJwk = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: jwk.kid,
    alg: "ES256",
    use: "sig"
  };
  return json({ keys: [publicJwk] });
}
async function authorize(request, env) {
  const url = new URL(request.url);
  const provider = url.searchParams.get("provider");
  const clientId = requiredParam(url, "client_id");
  const redirectUri = requiredParam(url, "redirect_uri");
  const responseType = requiredParam(url, "response_type");
  const scope = url.searchParams.get("scope") ?? "openid email profile";
  if (clientId !== env.OIDC_CLIENT_ID) {
    return oauthError("unauthorized_client", "Unknown client_id", 400);
  }
  if (!isAllowedRedirectUri(redirectUri, env)) {
    return oauthError("invalid_request", "Unexpected redirect_uri", 400);
  }
  if (responseType !== "code") {
    return oauthErrorRedirect(redirectUri, "unsupported_response_type", "Only response_type=code is supported", url.searchParams.get("state"));
  }
  const requestedScopes = scope.split(/\s+/).filter(Boolean);
  if (!requestedScopes.includes("openid")) {
    return oauthErrorRedirect(redirectUri, "invalid_scope", "openid scope is required", url.searchParams.get("state"));
  }
  if (requestedScopes.some((requestedScope) => !supportedScopes.has(requestedScope))) {
    return oauthErrorRedirect(redirectUri, "invalid_scope", "Unsupported scope", url.searchParams.get("state"));
  }
  if (provider == null) {
    return providerSelectionPage(url, env);
  }
  if (!enabledProviders(env).includes(provider)) {
    return oauthErrorRedirect(redirectUri, "invalid_request", `Provider ${provider} is not enabled`, url.searchParams.get("state"));
  }
  const brokerState = randomString();
  const state = {
    provider,
    clientId,
    redirectUri,
    scope,
    state: url.searchParams.get("state"),
    nonce: url.searchParams.get("nonce")
  };
  await authStore(env).putState(brokerState, state);
  return Response.redirect(providerAuthorizeUrl(provider, brokerState, env), 302);
}
async function oauthCallback(request, env, provider) {
  const url = new URL(request.url);
  const code = requiredParam(url, "code");
  const brokerState = requiredParam(url, "state");
  const state = await authStore(env).consumeState(brokerState);
  if (state == null || state.provider !== provider) {
    return json({ error: "invalid_state" }, 400);
  }
  const profile = provider === "github" ? await githubProfile(code, env) : await discordProfile(code, env);
  const oidcCode = randomString();
  const record = {
    clientId: state.clientId,
    redirectUri: state.redirectUri,
    scope: state.scope,
    nonce: state.nonce,
    profile
  };
  await authStore(env).putCode(oidcCode, record);
  const redirect = new URL(state.redirectUri);
  redirect.searchParams.set("code", oidcCode);
  if (state.state != null) {
    redirect.searchParams.set("state", state.state);
  }
  return Response.redirect(redirect.toString(), 302);
}
async function token(request, env) {
  const body = await request.formData();
  const grantType = String(body.get("grant_type") ?? "");
  const code = String(body.get("code") ?? "");
  const redirectUri = String(body.get("redirect_uri") ?? "");
  const client = tokenClientAuth(request, body);
  if (grantType !== "authorization_code") {
    return json({ error: "unsupported_grant_type" }, 400);
  }
  if (client.clientId !== env.OIDC_CLIENT_ID || client.clientSecret !== env.OIDC_CLIENT_SECRET) {
    return json({ error: "invalid_client" }, 401);
  }
  const record = await authStore(env).consumeCode(code);
  if (record == null) {
    return json({ error: "invalid_grant" }, 400);
  }
  if (record.clientId !== client.clientId || record.redirectUri !== redirectUri) {
    return json({ error: "invalid_grant" }, 400);
  }
  const now = Math.floor(Date.now() / 1e3);
  const idToken = await signJwt(
    {
      iss: normalizedIssuer(env),
      sub: record.profile.sub,
      aud: env.OIDC_CLIENT_ID,
      iat: now,
      exp: now + 900,
      nonce: record.nonce ?? void 0,
      email: record.profile.email ?? void 0,
      email_verified: record.profile.emailVerified ?? void 0,
      name: record.profile.name,
      preferred_username: record.profile.preferredUsername,
      provider: record.profile.provider,
      github_id: record.profile.githubId,
      github_login: record.profile.githubLogin,
      discord_id: record.profile.discordId,
      discord_username: record.profile.discordUsername,
      zt_principals: record.profile.ztPrincipals
    },
    env
  );
  const accessToken = randomString();
  await authStore(env).putAccessToken(accessToken, record.profile);
  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 900,
    id_token: idToken,
    scope: record.scope
  });
}
async function userinfo(request, env) {
  const auth = request.headers.get("authorization") ?? "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (match == null) {
    return json({ error: "invalid_token" }, 401);
  }
  const profile = await authStore(env).getAccessToken(match[1]);
  if (profile == null) {
    return json({ error: "invalid_token" }, 401);
  }
  return json(profileClaims(profile));
}
async function githubProfile(code, env) {
  requireEnv(env.GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID");
  requireEnv(env.GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET");
  const token2 = await formPost("https://github.com/login/oauth/access_token", {
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: `${normalizedIssuer(env)}/callback/github`
  }, { Accept: "application/json" });
  const accessToken = String(token2.access_token ?? "");
  if (accessToken === "") {
    throw new Error("GitHub did not return access_token");
  }
  const user = await fetchJson("https://api.github.com/user", {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "cloudflare-zero-trust-identity-broker"
  });
  const emails = await fetchJson("https://api.github.com/user/emails", {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "cloudflare-zero-trust-identity-broker"
  }).catch(() => []);
  const teams = await githubTeams(accessToken);
  const emailRecord = emails.find((email2) => email2.primary === true && email2.verified === true) ?? emails.find((email2) => email2.verified === true);
  const email = typeof emailRecord?.email === "string" ? emailRecord.email : null;
  if (email == null) {
    throw new Error("GitHub account has no verified email");
  }
  const id = String(user.id);
  const login = String(user.login);
  const principals = /* @__PURE__ */ new Set();
  principals.add(`github:user:${id}`);
  for (const team of teams) {
    principals.add(`github:team_id:${team.id}`);
  }
  return {
    sub: `github:${id}`,
    email,
    emailVerified: true,
    name: typeof user.name === "string" ? user.name : login,
    preferredUsername: login,
    provider: "github",
    githubId: id,
    githubLogin: login,
    ztPrincipals: [...principals]
  };
}
async function githubTeams(accessToken) {
  const teams = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await fetchJson(
      `https://api.github.com/user/teams?per_page=100&page=${page}`,
      {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "cloudflare-zero-trust-identity-broker"
      }
    ).catch(() => []);
    teams.push(...batch);
    if (batch.length < 100) break;
  }
  return teams;
}
async function discordProfile(code, env) {
  requireEnv(env.DISCORD_CLIENT_ID, "DISCORD_CLIENT_ID");
  requireEnv(env.DISCORD_CLIENT_SECRET, "DISCORD_CLIENT_SECRET");
  const token2 = await formPost("https://discord.com/api/oauth2/token", {
    grant_type: "authorization_code",
    client_id: env.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    code,
    redirect_uri: `${normalizedIssuer(env)}/callback/discord`
  });
  const accessToken = String(token2.access_token ?? "");
  if (accessToken === "") {
    throw new Error("Discord did not return access_token");
  }
  const user = await fetchJson("https://discord.com/api/users/@me", {
    Authorization: `Bearer ${accessToken}`
  });
  const guilds = await fetchJson("https://discord.com/api/users/@me/guilds", {
    Authorization: `Bearer ${accessToken}`
  }).catch(() => []);
  const id = String(user.id);
  const username = String(user.username);
  const email = typeof user.email === "string" && user.verified === true ? user.email : null;
  if (email == null) {
    throw new Error("Discord account has no verified email");
  }
  const principals = /* @__PURE__ */ new Set();
  principals.add(`discord:user:${id}`);
  for (const guild of guilds) {
    if (typeof guild.id === "string") {
      principals.add(`discord:guild:${guild.id}`);
    }
  }
  for (const guildId of commaList(env.DISCORD_ROLE_GUILD_IDS)) {
    const member = await fetchJson(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
      Authorization: `Bearer ${accessToken}`
    }).catch(() => null);
    for (const roleId of member?.roles ?? []) {
      principals.add(`discord:role:${guildId}/${roleId}`);
    }
  }
  return {
    sub: `discord:${id}`,
    email,
    emailVerified: true,
    name: typeof user.global_name === "string" ? user.global_name : username,
    preferredUsername: username,
    provider: "discord",
    discordId: id,
    discordUsername: username,
    ztPrincipals: [...principals]
  };
}
function providerAuthorizeUrl(provider, state, env) {
  if (provider === "github") {
    const url2 = new URL("https://github.com/login/oauth/authorize");
    url2.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    url2.searchParams.set("redirect_uri", `${normalizedIssuer(env)}/callback/github`);
    url2.searchParams.set("scope", "read:user user:email read:org");
    url2.searchParams.set("state", state);
    return url2.toString();
  }
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
  url.searchParams.set("redirect_uri", `${normalizedIssuer(env)}/callback/discord`);
  url.searchParams.set("scope", "identify email guilds guilds.members.read");
  url.searchParams.set("state", state);
  return url.toString();
}
function providerSelectionPage(requestUrl, env) {
  const providers = enabledProviders(env);
  const actions = providers.map((provider) => {
    const url = new URL(requestUrl.toString());
    url.searchParams.set("provider", provider);
    return {
      href: url.pathname + url.search,
      label: provider === "discord" ? "Log in with Discord" : "Log in with GitHub"
    };
  });
  return identityPage(env, {
    actions
  });
}
function home(env) {
  const redirectUrl = env.HOME_REDIRECT_URL?.trim();
  if (redirectUrl) {
    return Response.redirect(redirectUrl, 302);
  }
  return identityPage(env, {
    actions: []
  });
}
function identityPage(env, options) {
  const brand = env.BRAND_NAME?.trim() || "Enhancer Identity";
  const actionHtml = options.actions.length === 0 ? "" : options.actions.map((action) => `
        <a class="button" href="${escapeHtml(action.href)}">
          <span>${escapeHtml(action.label)}</span>
        </a>
      `).join("");
  const footerText = `This is not a Cloudflare page. It is ${brand}'s private identity gateway.`;
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(brand)}</title>
  <style>
    :root {
      --bg: oklch(16% .008 270);
      --card: oklch(18.5% .009 270);
      --border: oklch(28% .012 270);
      --border-hover: oklch(40% .014 270);
      --text: oklch(96% .003 270);
      --text-faint: oklch(42% .012 270);
      color-scheme: dark;
      font-family: "Geist", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * { box-sizing: border-box; }

    html,
    body {
      height: 100%;
      margin: 0;
    }

    body {
      display: grid;
      place-items: center;
      padding: 24px;
      color: var(--text);
      background:
        radial-gradient(ellipse 900px 500px at 50% 0%, oklch(24% .014 270 / .5), transparent),
        var(--bg);
      background-attachment: fixed;
      -webkit-font-smoothing: antialiased;
    }

    .shell {
      width: 100%;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }

    .card {
      width: 100%;
      max-width: 360px;
      display: flex;
      flex-direction: column;
      align-items: stretch;
    }

    .brand { margin-bottom: 28px; }

    .brand h1 {
      margin: 0;
      color: var(--text);
      font-size: 15px;
      font-weight: 500;
      letter-spacing: -0.01em;
    }

    .buttons {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .button {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 9px 16px;
      border-radius: 6px;
      color: var(--text);
      text-decoration: none;
      background: oklch(70% .006 270 / .06);
      border: 1px solid var(--border);
      font: inherit;
      font-size: 13px;
      font-weight: 500;
      transition: border-color .15s ease, background .15s ease;
    }

    .button:hover {
      border-color: var(--border-hover);
      background: oklch(70% .006 270 / .1);
    }

    .button:active {
      background: oklch(70% .006 270 / .14);
    }

    .button:focus-visible {
      outline: 2px solid var(--text);
      outline-offset: 2px;
    }

    .footer {
      max-width: 320px;
      margin: 28px 0 0;
      color: var(--text-faint);
      font-size: 11px;
      line-height: 1.6;
    }

    @media (max-width: 560px) {
      body { padding: 18px; }
    }

    @media (prefers-reduced-motion: reduce) {
      .button { transition: none; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <div class="card">
      <div class="brand">
        <h1>Log in with ${escapeHtml(brand)}</h1>
      </div>
      <div class="buttons">${actionHtml}</div>
    </div>
    <footer class="footer">${escapeHtml(footerText)}</footer>
  </main>
</body>
</html>`, {
    headers: htmlHeaders()
  });
}
function enabledProviders(env) {
  const providers = [];
  if (env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) providers.push("discord");
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) providers.push("github");
  return providers;
}
function profileClaims(profile) {
  return {
    sub: profile.sub,
    email: profile.email ?? void 0,
    email_verified: profile.emailVerified,
    name: profile.name,
    preferred_username: profile.preferredUsername,
    provider: profile.provider,
    github_id: profile.githubId,
    github_login: profile.githubLogin,
    discord_id: profile.discordId,
    discord_username: profile.discordUsername,
    zt_principals: profile.ztPrincipals
  };
}
async function signJwt(payload, env) {
  const jwk = privateJwk(env);
  const header = { alg: "ES256", typ: "JWT", kid: jwk.kid };
  const encodedHeader = base64UrlJson(header);
  const encodedPayload = base64UrlJson(removeUndefined(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(signingInput));
  const joseSignature = ecdsaSignatureToJose(new Uint8Array(signature));
  return `${signingInput}.${base64Url(joseSignature)}`;
}
function ecdsaSignatureToJose(signature) {
  if (signature.length === 64) return signature;
  let offset = 0;
  if (signature[offset++] !== 48) throw new Error("Invalid DER signature");
  const sequenceLength = signature[offset++];
  if (sequenceLength + 2 !== signature.length) throw new Error("Invalid DER signature length");
  if (signature[offset++] !== 2) throw new Error("Invalid DER signature");
  const rLength = signature[offset++];
  const r = signature.slice(offset, offset + rLength);
  offset += rLength;
  if (signature[offset++] !== 2) throw new Error("Invalid DER signature");
  const sLength = signature[offset++];
  const s = signature.slice(offset, offset + sLength);
  return concatBytes(leftPad(stripLeadingZeroes(r), 32), leftPad(stripLeadingZeroes(s), 32));
}
function stripLeadingZeroes(bytes) {
  let offset = 0;
  while (offset < bytes.length - 1 && bytes[offset] === 0) offset++;
  return bytes.slice(offset);
}
function leftPad(bytes, length) {
  if (bytes.length > length) return bytes.slice(bytes.length - length);
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
function privateJwk(env) {
  const jwk = JSON.parse(env.JWT_PRIVATE_JWK);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.d == null) {
    throw new Error("JWT_PRIVATE_JWK must be a private P-256 JWK");
  }
  if (jwk.kid == null) jwk.kid = "identity-broker-1";
  return jwk;
}
function tokenClientAuth(request, body) {
  const auth = request.headers.get("authorization") ?? "";
  const match = auth.match(/^Basic\s+(.+)$/i);
  if (match != null) {
    const [clientId, clientSecret] = atob(match[1]).split(":", 2);
    return { clientId, clientSecret };
  }
  return {
    clientId: String(body.get("client_id") ?? ""),
    clientSecret: String(body.get("client_secret") ?? "")
  };
}
async function formPost(url, form, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers
    },
    body: new URLSearchParams(form)
  });
  if (!response.ok) {
    throw new Error(`POST ${url} failed: ${response.status}`);
  }
  return response.json();
}
async function fetchJson(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`GET ${url} failed: ${response.status}`);
  }
  return response.json();
}
function authStore(env) {
  return env.AUTH_STORE.get(env.AUTH_STORE.idFromName("identity-broker-auth"));
}
async function enforceRateLimit(request, env, name, limit, periodSeconds) {
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const ok = await authStore(env).rateLimit(`${name}:${ip}`, limit, periodSeconds);
  return ok ? null : json({ error: "rate_limited" }, 429);
}
function isAllowedRedirectUri(redirectUri, env) {
  if (env.CLOUDFLARE_CALLBACK_URL == null || env.CLOUDFLARE_CALLBACK_URL.trim() === "") return false;
  try {
    const requested = new URL(redirectUri);
    const registered = new URL(env.CLOUDFLARE_CALLBACK_URL);
    return requested.protocol === "https:" && requested.username === "" && requested.password === "" && requested.hash === "" && requested.toString() === registered.toString();
  } catch {
    return false;
  }
}
function oauthError(error, description, status) {
  return json({ error, error_description: description }, status);
}
function oauthErrorRedirect(redirectUri, error, description, state) {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("error", error);
  redirect.searchParams.set("error_description", description);
  if (state != null) redirect.searchParams.set("state", state);
  return Response.redirect(redirect.toString(), 302);
}
function requiredParam(url, name) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") {
    throw new Error(`Missing required parameter: ${name}`);
  }
  return value;
}
function requireEnv(value, name) {
  if (value == null || value === "") {
    throw new Error(`${name} is required`);
  }
}
function normalizedIssuer(env) {
  return env.ISSUER.replace(/\/+$/, "");
}
function randomString() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}
function base64UrlJson(value) {
  return base64Url(encoder.encode(JSON.stringify(value)));
}
function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function json(value, status = 200) {
  return new Response(JSON.stringify(removeUndefined(value), null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}
function htmlHeaders() {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff"
  };
}
function removeUndefined(value) {
  if (Array.isArray(value)) return value.map(removeUndefined);
  if (value != null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== void 0).map(([k, v]) => [k, removeUndefined(v)]));
  }
  return value;
}
function commaList(value) {
  return (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
function escapeHtml(value) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
export {
  IdentityBrokerAuthStore,
  index_default as default
};
