terraform {
  required_version = ">= 1.3.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

locals {
  identity_broker_enabled      = var.identity_broker != null && var.identity_broker.enabled
  identity_broker_issuer       = local.identity_broker_enabled ? trimsuffix(var.identity_broker.issuer, "/") : null
  identity_broker_callback_url = local.identity_broker_enabled ? "https://${var.identity_broker.cloudflare_team_name}.cloudflareaccess.com/cdn-cgi/access/callback" : null

  identity_provider_ids = merge(
    var.existing_identity_provider_ids,
    { for key, provider in cloudflare_zero_trust_access_identity_provider.this : key => provider.id }
  )

  identity_broker_bindings = local.identity_broker_enabled ? concat(
    [
      {
        name       = "AUTH_STORE"
        type       = "durable_object_namespace"
        class_name = "IdentityBrokerAuthStore"
        text       = null
      },
      {
        name       = "ISSUER"
        type       = "plain_text"
        class_name = null
        text       = local.identity_broker_issuer
      },
      {
        name       = "OIDC_CLIENT_ID"
        type       = "plain_text"
        class_name = null
        text       = var.identity_broker.oidc_client_id
      },
      {
        name       = "OIDC_CLIENT_SECRET"
        type       = "secret_text"
        class_name = null
        text       = var.identity_broker.oidc_client_secret
      },
      {
        name       = "JWT_PRIVATE_JWK"
        type       = "secret_text"
        class_name = null
        text       = var.identity_broker.jwt_private_jwk
      },
      {
        name       = "DISCORD_ROLE_GUILD_IDS"
        type       = "plain_text"
        class_name = null
        text       = join(",", var.identity_broker.discord_role_guild_ids)
      },
      {
        name       = "BRAND_NAME"
        type       = "plain_text"
        class_name = null
        text       = var.identity_broker.brand_name
      },
      {
        name       = "CLOUDFLARE_CALLBACK_URL"
        type       = "plain_text"
        class_name = null
        text       = local.identity_broker_callback_url
      },
    ],
    var.identity_broker.home_redirect_url == null ? [] : [
      {
        name       = "HOME_REDIRECT_URL"
        type       = "plain_text"
        class_name = null
        text       = var.identity_broker.home_redirect_url
      }
    ],
    var.identity_broker.github == null ? [] : [
      {
        name       = "GITHUB_CLIENT_ID"
        type       = "plain_text"
        class_name = null
        text       = var.identity_broker.github.client_id
      },
      {
        name       = "GITHUB_CLIENT_SECRET"
        type       = "secret_text"
        class_name = null
        text       = var.identity_broker.github.client_secret
      }
    ],
    var.identity_broker.discord == null ? [] : [
      {
        name       = "DISCORD_CLIENT_ID"
        type       = "plain_text"
        class_name = null
        text       = var.identity_broker.discord.client_id
      },
      {
        name       = "DISCORD_CLIENT_SECRET"
        type       = "secret_text"
        class_name = null
        text       = var.identity_broker.discord.client_secret
      }
    ]
  ) : []

  user_principals = {
    for user_key, user in var.users : user_key => distinct([
      for principal in user.principals : lookup(var.principal_aliases, principal, principal)
    ])
  }

  group_user_principals = {
    for group_key, group in var.groups : group_key => flatten([
      for user_key in group.user_keys : local.user_principals[user_key]
    ])
  }

  group_direct_principals = {
    for group_key, group in var.groups : group_key => flatten([
      for principal in group.principals : startswith(principal, "user:") ? local.user_principals[trimprefix(principal, "user:")] : [lookup(var.principal_aliases, principal, principal)]
    ])
  }

  group_principals = {
    for group_key, group in var.groups : group_key => distinct(concat(
      local.group_user_principals[group_key],
      local.group_direct_principals[group_key]
    ))
  }

  group_email_principals = {
    for group_key, principals in local.group_principals : group_key => [
      for principal in principals : trimprefix(principal, "email:")
      if startswith(principal, "email:")
    ]
  }

  group_oidc_principals = {
    for group_key, principals in local.group_principals : group_key => [
      for principal in principals : principal
      if !startswith(principal, "email:")
    ]
  }
}

resource "cloudflare_workers_script" "identity_broker" {
  count              = local.identity_broker_enabled ? 1 : 0
  account_id         = var.cloudflare_account_id
  script_name        = var.identity_broker.script_name
  main_module        = "index.js"
  compatibility_date = var.identity_broker.compatibility_date
  content_file       = "${path.module}/identity-broker/src/index.js"
  content_sha256     = filesha256("${path.module}/identity-broker/src/index.js")
  bindings           = local.identity_broker_bindings
  migrations = {
    new_tag            = var.identity_broker.durable_object_migration_tag
    new_sqlite_classes = ["IdentityBrokerAuthStore"]
  }

  lifecycle {
    precondition {
      condition     = startswith(local.identity_broker_issuer, "https://")
      error_message = "identity_broker.issuer must use https://."
    }

    precondition {
      condition     = var.identity_broker.custom_domain == null || local.identity_broker_issuer == "https://${var.identity_broker.custom_domain.hostname}"
      error_message = "identity_broker.issuer must exactly match https://identity_broker.custom_domain.hostname."
    }

    precondition {
      condition     = can(regex("^[a-z0-9-]+$", var.identity_broker.cloudflare_team_name))
      error_message = "identity_broker.cloudflare_team_name must be the Cloudflare Zero Trust team subdomain, for example my-team from https://my-team.cloudflareaccess.com."
    }
  }
}

resource "cloudflare_workers_custom_domain" "identity_broker" {
  count      = local.identity_broker_enabled && var.identity_broker.custom_domain != null ? 1 : 0
  account_id = var.cloudflare_account_id
  hostname   = var.identity_broker.custom_domain.hostname
  service    = cloudflare_workers_script.identity_broker[0].script_name
  zone_id    = var.identity_broker.custom_domain.zone_id
  zone_name  = var.identity_broker.custom_domain.zone_name
}

resource "cloudflare_zero_trust_access_identity_provider" "this" {
  for_each   = toset(keys(nonsensitive(var.identity_providers)))
  account_id = var.cloudflare_account_id
  name       = nonsensitive(var.identity_providers[each.key].name)
  type       = nonsensitive(var.identity_providers[each.key].type)
  config     = var.identity_providers[each.key].config
}

resource "cloudflare_zero_trust_access_group" "this" {
  for_each   = var.groups
  account_id = var.cloudflare_account_id
  name       = each.value.name

  include = concat(
    [for email in local.group_email_principals[each.key] : { email = { email = email } }],
    [
      for principal in local.group_oidc_principals[each.key] : {
        oidc = {
          identity_provider_id = local.identity_provider_ids[var.principal_idp_key]
          claim_name           = var.principal_claim_name
          claim_value          = principal
        }
      }
    ],
    flatten([
      for user_key in each.value.user_keys : [
        for claim in var.users[user_key].oidc_claims : {
          oidc = {
            identity_provider_id = local.identity_provider_ids[claim.idp_key]
            claim_name           = claim.claim_name
            claim_value          = claim.claim_value
          }
        }
      ]
    ]),
    [for email in each.value.include.emails : { email = { email = email } }],
    [for domain in each.value.include.email_domains : { email_domain = { domain = domain } }],
    each.value.include.everyone ? [{ everyone = {} }] : [],
    [for idp_key in each.value.include.idp_keys : { login_method = { id = local.identity_provider_ids[idp_key] } }],
    each.value.github == null ? [] : (
      length(each.value.github.teams) == 0 ? [
        {
          github_organization = {
            identity_provider_id = local.identity_provider_ids[each.value.github.idp_key]
            name                 = each.value.github.org
            team                 = null
          }
        }
        ] : [
        for team in each.value.github.teams : {
          github_organization = {
            identity_provider_id = local.identity_provider_ids[each.value.github.idp_key]
            name                 = each.value.github.org
            team                 = team
          }
        }
      ]
    )
  )

  lifecycle {
    precondition {
      condition     = var.principal_idp_key != null || length(local.group_oidc_principals[each.key]) == 0
      error_message = "principal_idp_key must be set when groups use non-email principals."
    }
  }

  require = concat(
    each.value.require.github == null ? [] : (
      length(each.value.require.github.teams) == 0 ? [
        {
          github_organization = {
            identity_provider_id = local.identity_provider_ids[each.value.require.github.idp_key]
            name                 = each.value.require.github.org
            team                 = null
          }
        }
        ] : [
        for team in each.value.require.github.teams : {
          github_organization = {
            identity_provider_id = local.identity_provider_ids[each.value.require.github.idp_key]
            name                 = each.value.require.github.org
            team                 = team
          }
        }
      ]
    )
  )
}

resource "cloudflare_zero_trust_access_application" "this" {
  for_each                  = var.applications
  account_id                = var.cloudflare_account_id
  name                      = each.value.name
  domain                    = each.value.domain
  type                      = each.value.type
  session_duration          = each.value.session_duration
  allowed_idps              = [for idp_key in each.value.allowed_idp_keys : local.identity_provider_ids[idp_key]]
  auto_redirect_to_identity = each.value.auto_redirect_to_identity
  app_launcher_visible      = each.value.app_launcher_visible

  policies = [
    for group_key in each.value.group_keys : {
      name       = "allow-${group_key}"
      decision   = "allow"
      precedence = index(each.value.group_keys, group_key) + 1
      include = [{
        group = {
          id = cloudflare_zero_trust_access_group.this[group_key].id
        }
      }]
    }
  ]

  lifecycle {
    precondition {
      condition     = length(each.value.allowed_idp_keys) > 0 || length(local.identity_provider_ids) == 0
      error_message = "applications must explicitly set allowed_idp_keys when identity providers are configured."
    }
  }
}
