# Identity Broker Worker

Cloudflare Worker that acts as a small OIDC provider for Cloudflare Access. It lets users sign in with GitHub or Discord OAuth and emits immutable provider-specific principal strings in the `zt_principals` OIDC claim. A verified provider email is required for Cloudflare's user profile, but email is not emitted as an authorization principal.

## Principal Strings

The Worker emits claims such as:

```text
github:user:123456
github:team_id:123456
discord:user:276784124814032897
discord:guild:123456789012345678
discord:role:123456789012345678/987654321098765432
```

Use Terraform `principal_aliases` for friendly names such as `discord:role:enhancer/developer` mapped to canonical ID-based principal strings.

## Setup With Terraform

The Terraform module in the repository can manage this Worker directly:

- Creates the SQLite-backed Durable Object used for auth state, authorization codes, access tokens, and rate limits.
- Uploads `src/index.js` as the Worker script.
- Adds plain text and secret bindings.
- Optionally attaches a Workers custom domain such as `identity.enhancer.at`.
- Serves a minimal branded status page on `/` unless `home_redirect_url` is set.

You only need to generate the signing JWK and pass secrets to Terraform.

Install dependencies if you want to use the helper script:


```bash
npm install
```

Generate JWT signing key:

```bash
npm run generate-key
```

Put the generated JSON in Terraform as `identity_broker_jwt_private_jwk`. The OIDC client secret must be the same value in the Worker binding and Cloudflare Access OIDC IdP config; the module wires this automatically when using `identity_broker`.

Example:

```hcl
identity_broker = {
  enabled            = true
  issuer             = "https://identity.enhancer.at"
  cloudflare_team_name = "my-team"
  brand_name         = "Enhancer Identity"
  home_redirect_url  = null
  oidc_client_id     = "cloudflare-access"
  oidc_client_secret = var.identity_broker_client_secret
  jwt_private_jwk    = var.identity_broker_jwt_private_jwk

  github = {
    client_id     = local.github_client_id
    client_secret = var.github_client_secret
  }

  discord = {
    client_id     = local.discord_client_id
    client_secret = var.discord_client_secret
  }

  custom_domain = {
    hostname  = "identity.enhancer.at"
    zone_name = "enhancer.at"
  }
}
```

See `examples/identity-broker`.

## Home Page And Redirects

By default, `https://identity.enhancer.at/` renders a minimal branded status page. To redirect the root page somewhere else, set:

```hcl
identity_broker = {
  home_redirect_url = "https://test-o2.enhancer.at"
}
```

Only `/` redirects. OIDC endpoints such as `/authorize`, `/token`, `/jwks.json`, and callbacks remain active.

## Switching Hostnames

Use one hostname value and derive the issuer from it:

```hcl
locals {
  identity_broker_hostname = "identity.enhancer.at"
  identity_broker_issuer   = "https://${local.identity_broker_hostname}"
}
```

For a test broker, change only:

```hcl
identity_broker_hostname = "test-identity.enhancer.at"
```

Then update OAuth callbacks:

```text
https://test-identity.enhancer.at/callback/github
https://test-identity.enhancer.at/callback/discord
```

## Optional Wrangler Development

`wrangler.jsonc` is kept for local development and dry-runs, but production deployment is expected to be managed by Terraform. If using Wrangler manually, update its placeholder values and secrets yourself.

## Worker Vars

Edit `wrangler.jsonc`:

```jsonc
{
  "vars": {
    "ISSUER": "https://identity.enhancer.at",
    "BRAND_NAME": "Enhancer Identity",
    "OIDC_CLIENT_ID": "cloudflare-access",
    "CLOUDFLARE_CALLBACK_URL": "https://<team>.cloudflareaccess.com/cdn-cgi/access/callback",
    "GITHUB_CLIENT_ID": "...",
    "DISCORD_CLIENT_ID": "...",
    "DISCORD_ROLE_GUILD_IDS": "123456789012345678"
  }
}
```

`DISCORD_ROLE_GUILD_IDS` is optional. Role lookup is only attempted for listed guild IDs to avoid making many Discord API calls on every login.

## GitHub OAuth App

Callback URL:

```text
https://identity.enhancer.at/callback/github
```

The Worker requests scopes:

```text
read:user user:email read:org
```

`read:org` is needed to discover GitHub team IDs for `github:team_id:*` principals.

## Discord OAuth App

Callback URL:

```text
https://identity.enhancer.at/callback/discord
```

The Worker requests scopes:

```text
identify email guilds guilds.members.read
```

`guilds.members.read` is needed for `discord:role:*` principals.

## Cloudflare Access OIDC

Configure Cloudflare Generic OIDC with:

```text
Auth URL:  https://identity.enhancer.at/authorize
Token URL: https://identity.enhancer.at/token
JWKS URL:  https://identity.enhancer.at/jwks.json
Scopes:    openid email profile
Claims:    zt_principals github_id github_login discord_id discord_username
```

This repository's Terraform module can create that IdP for you. See `examples/identity-broker`.

## Terraform Apply

Run Terraform from your consuming project or from `examples/identity-broker` after setting variables. Terraform will create the Worker and Cloudflare Access OIDC identity provider.
