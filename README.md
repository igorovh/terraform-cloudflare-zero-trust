# terraform-cloudflare-zero-trust

Terraform module for Cloudflare Zero Trust Access applications, groups, policies, and optional identity providers.

## Quick Start

```hcl
module "zero_trust" {
  source = "git::https://github.com/igorovh/terraform-cloudflare-zero-trust.git?ref=v0.1.0"

  cloudflare_account_id = var.cloudflare_account_id

  groups = {
    admins = {
      name = "Admins"

      include = {
        emails = ["admin@example.com"]
      }
    }
  }

  applications = {
    grafana = {
      name       = "Grafana"
      domain     = "grafana.example.com"
      group_keys = ["admins"]
    }
  }
}
```

Configure the Cloudflare provider, then run `terraform init` and `terraform apply` from the consuming project.

## Examples and Docs

- [Examples](examples/): [minimal](examples/minimal/), [GitHub](examples/github/), [custom OIDC](examples/custom-oidc/), and [Identity Broker](examples/identity-broker/).
- [Identity Broker Worker documentation](identity-broker/README.md)

## Cloudflare Token Permissions

The Cloudflare API token needs write access for Zero Trust Access applications, policies, groups, and identity providers.

At minimum, include permissions for Access applications and `Access: Organizations, Identity Providers, and Groups Write`.

If `identity_broker` is enabled, also include:

- `Workers Scripts Write`
- `Workers Scripts Read`
- permissions required to create Durable Object migrations for the Worker script

If using `identity_broker.custom_domain`, include permissions needed to manage Worker custom domains for the target zone.

## GitHub Login

```hcl
module "zero_trust" {
  source = "git::https://github.com/igorovh/terraform-cloudflare-zero-trust.git?ref=v0.1.0"

  cloudflare_account_id = var.cloudflare_account_id

  identity_providers = {
    github = {
      name = "GitHub"
      type = "github"
      config = {
        client_id     = var.github_client_id
        client_secret = var.github_client_secret
      }
    }
  }

  groups = {
    admins = {
      name = "GitHub Admins"

      github = {
        idp_key = "github"
        org     = "my-org"
        teams   = ["admins"]
      }
    }
  }

  applications = {
    grafana = {
      name             = "Grafana"
      domain           = "grafana.example.com"
      group_keys       = ["admins"]
      allowed_idp_keys = ["github"]
    }
  }
}
```

## Users, Principals, And Groups

Cloudflare Access does not create users as Terraform resources. Users authenticate through an identity provider, and Access policies match them by email, login method, IdP claims, GitHub organization/team, or similar rules.

This module provides a local `users` abstraction so you can declare a person once and add them to groups by key or by `user:<key>` principal.

User identities are all declared as principals. Use `email:<address>` for email/OTP identities and provider-specific principals for the Identity Broker.

For native Cloudflare IdPs, email-based access is the simplest model. For per-user GitHub/Discord IDs, GitHub team IDs, Discord guilds, and Discord roles, use the Worker in `identity-broker/`. The Worker requires a verified provider email for Cloudflare's user profile, but authorization should use the `zt_principals` OIDC claim such as:

```text
github:user:123456
github:team_id:987654
discord:user:276784124814032897
discord:guild:123456789012345678
discord:role:123456789012345678/987654321098765432
```

Use `principal_aliases` for friendly names while keeping canonical ID-based principals as the security boundary.

```hcl
module "zero_trust" {
  source = "git::https://github.com/igorovh/terraform-cloudflare-zero-trust.git?ref=v0.1.0"

  cloudflare_account_id = var.cloudflare_account_id
  principal_idp_key      = "identity_broker"

  principal_aliases = {
    "github:team:enhancer/developers" = "github:team_id:987654"
    "discord:role:enhancer/developer" = "discord:role:123456789012345678/987654321098765432"
  }

  identity_providers = {
    identity_broker = {
      name = "Identity Broker"
      type = "oidc"
      config = {
        client_id        = "cloudflare-access"
        client_secret    = var.identity_broker_client_secret
        auth_url         = "https://identity.enhancer.at/authorize"
        token_url        = "https://identity.enhancer.at/token"
        certs_url        = "https://identity.enhancer.at/jwks.json"
        email_claim_name = "email"
        scopes           = ["openid", "email", "profile"]
        claims           = ["zt_principals", "github_id", "github_login", "discord_id", "discord_username"]
      }
    }
  }

  users = {
    igor = {
      principals = [
        "email:igor@enhancer.at",
        "github:user:123456",
        "discord:user:276784124814032897"
      ]
    }
  }

  groups = {
    devs = {
      name = "Developers"
      principals = [
        "user:igor",
        "github:team:enhancer/developers"
      ]
    }
  }

  applications = {
    test_o2 = {
      name             = "Enhancer OpenObserve (Test)"
      domain           = "test-o2.enhancer.at"
      group_keys       = ["devs"]
      allowed_idp_keys = ["identity_broker"]
    }
  }
}
```

### Identity Provider Merging

Cloudflare Access treats each identity provider as a separate source — different IdPs produce **separate Cloudflare identities** even for the same person.

- Logging in via the **identity broker** (GitHub or Discord) and via a **separate IdP** (e.g., Cloudflare's `onetimepin`) creates **two identities**.
- Logging in via **GitHub** and **Discord** through the **same identity broker** creates **one identity** — the broker is a single OIDC provider to Cloudflare; the upstream choice is internal.

The module can manage the Identity Broker Worker through `identity_broker`. See `identity-broker/README.md` and `examples/identity-broker` for setup.

The broker serves a minimal branded page at `/`. To redirect the root page elsewhere while keeping OIDC endpoints active, set:

```hcl
identity_broker = {
  home_redirect_url = "https://test-o2.enhancer.at"
}
```

To switch between `identity.enhancer.at` and `test-identity.enhancer.at`, keep a single hostname local and derive the issuer from it:

```hcl
locals {
  identity_broker_hostname = "test-identity.enhancer.at"
  identity_broker_issuer   = "https://${local.identity_broker_hostname}"
}
```

Remember to update GitHub and Discord OAuth callback URLs to match the selected hostname.

Set `identity_broker.cloudflare_team_name` to your Cloudflare Zero Trust team subdomain. The module derives the only accepted Cloudflare Access callback URL as:

```text
https://<team-name>.cloudflareaccess.com/cdn-cgi/access/callback
```

## Custom Identity Providers

Use `identity_providers` for any Cloudflare-supported type such as `github`, `google`, `oidc`, `saml`, `okta`, or `onetimepin`.

Use `existing_identity_provider_ids` when an identity provider is already configured outside this module and you only want to reference it from groups or applications.

## Security

OAuth/OIDC client secrets and the broker signing JWK are passed through Terraform. Terraform state will contain sensitive values used by providers and Worker secret bindings. Use encrypted remote state and restrict access to state files.

The module controls Cloudflare Access policy. It does not hide or firewall your origin server. If the origin is publicly reachable outside Cloudflare, secure it separately and validate Cloudflare Access JWTs at the origin where practical.

## Inputs

- `cloudflare_account_id`: Cloudflare account ID.
- `identity_providers`: Identity providers to create.
- `existing_identity_provider_ids`: Existing IdP IDs keyed by local name.
- `identity_broker`: Optional Terraform-managed Identity Broker Worker configuration.
- `users`: Local user/principal declarations that groups can reference.
- `principal_aliases`: Friendly aliases mapped to canonical principal strings.
- `principal_idp_key`: IdP key whose OIDC claim contains `zt_principals`.
- `principal_claim_name`: OIDC claim name used for principal matching. Defaults to `zt_principals`.
- `groups`: Cloudflare Access groups.
- `applications`: Cloudflare Access applications and generated allow policies.

## Outputs

- `identity_provider_ids`
- `identity_provider_redirect_urls`
- `group_ids`
- `application_ids`
- `application_auds`
