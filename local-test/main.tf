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
  cloudflare_account_id     = "f26b84abcda209983f6c31c14e5f281d"
  identity_broker_hostname  = "test-identity.enhancer.at"
  identity_broker_issuer    = "https://${local.identity_broker_hostname}"
  identity_broker_client_id = "cloudflare-access"
  discord_client_id         = "1520214812015988797"
  cloudflare_team_name      = "enhancer-trust"

  domain = "enhancer.at"
}

module "zero_trust" {
  source = "../"

  cloudflare_account_id = local.cloudflare_account_id
  principal_idp_key     = "identity_broker"

  identity_broker = {
    enabled              = true
    script_name          = "enhancer-test-identity-broker"
    issuer               = local.identity_broker_issuer
    cloudflare_team_name = local.cloudflare_team_name
    brand_name           = "Enhancer Identity"
    home_redirect_url    = "https://enhancer.at"
    oidc_client_id       = local.identity_broker_client_id
    oidc_client_secret   = var.identity_broker_client_secret
    jwt_private_jwk      = var.identity_broker_jwt_private_jwk

    discord = {
      client_id     = local.discord_client_id
      client_secret = var.discord_client_secret
    }

    discord_role_guild_ids = [

    ]

    custom_domain = {
      hostname  = local.identity_broker_hostname
      zone_name = local.domain
    }
  }

  principal_aliases = {}

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
    onetimepin = {
      name   = "Email (One-time PIN)"
      type   = "onetimepin"
      config = {}
    }
  }

  users = {
    igor = {
      principals = [
        "email:igor@enhancer.at",
        "discord:user:276784124814032897"
      ]
    }
  }

  groups = {
    devs = {
      name = "Developers"
      principals = [
        "user:igor",
      ]
    }
  }

  applications = {
    app = {
      name             = "Enhancer OpenObserve (Test)"
      domain           = "test-o2.${local.domain}"
      group_keys       = ["devs"]
      allowed_idp_keys = ["identity_broker", "onetimepin"]
    }
  }
}

output "identity_provider_ids" {
  value = module.zero_trust.identity_provider_ids
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

output "group_ids" {
  value = module.zero_trust.group_ids
}

output "application_ids" {
  value = module.zero_trust.application_ids
}
