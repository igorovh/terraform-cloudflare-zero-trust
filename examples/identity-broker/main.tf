terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

locals {
  identity_broker_hostname  = "identity.enhancer.at"
  identity_broker_issuer    = "https://${local.identity_broker_hostname}"
  identity_broker_client_id = "cloudflare-access"
  github_client_id          = "REPLACE_ME"
  discord_client_id         = "REPLACE_ME"
}

module "zero_trust" {
  source = "../../"

  cloudflare_account_id = var.cloudflare_account_id
  principal_idp_key     = "identity_broker"

  identity_broker = {
    enabled              = true
    script_name          = "enhancer-identity-broker"
    issuer               = local.identity_broker_issuer
    cloudflare_team_name = var.cloudflare_team_name
    brand_name           = "Enhancer Identity"
    home_redirect_url    = null
    oidc_client_id       = local.identity_broker_client_id
    oidc_client_secret   = var.identity_broker_client_secret
    jwt_private_jwk      = var.identity_broker_jwt_private_jwk

    github = {
      client_id     = local.github_client_id
      client_secret = var.github_client_secret
    }

    discord = {
      client_id     = local.discord_client_id
      client_secret = var.discord_client_secret
    }

    discord_role_guild_ids = [
      "REPLACE_ME_DISCORD_GUILD_ID"
    ]

    custom_domain = {
      hostname  = local.identity_broker_hostname
      zone_name = "enhancer.at"
    }
  }

  principal_aliases = {
    "github:team:enhancer/developers" = "github:team_id:REPLACE_ME_GITHUB_TEAM_ID"
    "discord:guild:enhancer"          = "discord:guild:REPLACE_ME_DISCORD_GUILD_ID"
    "discord:role:enhancer/developer" = "discord:role:REPLACE_ME_DISCORD_GUILD_ID/REPLACE_ME_DISCORD_ROLE_ID"
  }

  identity_providers = {
    identity_broker = {
      name = "Identity Broker"
      type = "oidc"
      config = {
        client_id        = local.identity_broker_client_id
        client_secret    = var.identity_broker_client_secret
        auth_url         = "${local.identity_broker_issuer}/authorize"
        token_url        = "${local.identity_broker_issuer}/token"
        certs_url        = "${local.identity_broker_issuer}/jwks.json"
        email_claim_name = "email"
        scopes           = ["openid", "email", "profile"]
        claims           = ["zt_principals", "github_id", "github_login", "discord_id", "discord_username"]
      }
    }
  }

  users = {
    igor = {
      principals = [
        "github:user:REPLACE_ME_GITHUB_USER_ID",
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
    app = {
      name             = "Enhancer OpenObserve (Test)"
      domain           = "test-o2.enhancer.at"
      group_keys       = ["devs"]
      allowed_idp_keys = ["identity_broker"]
    }
  }
}

output "identity_provider_redirect_urls" {
  value = module.zero_trust.identity_provider_redirect_urls
}

output "identity_broker_worker_script_name" {
  value = module.zero_trust.identity_broker_worker_script_name
}

output "identity_broker_worker_custom_domain" {
  value = module.zero_trust.identity_broker_worker_custom_domain
}
