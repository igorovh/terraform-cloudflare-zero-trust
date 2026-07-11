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

module "zero_trust" {
  source = "../../"

  cloudflare_account_id = var.cloudflare_account_id

  identity_providers = {
    oidc = {
      name = var.oidc_name
      type = "oidc"
      config = {
        client_id        = var.oidc_client_id
        client_secret    = var.oidc_client_secret
        auth_url         = var.oidc_auth_url
        token_url        = var.oidc_token_url
        certs_url        = var.oidc_certs_url
        scopes           = ["openid", "email", "profile"]
        email_claim_name = "email"
      }
    }
  }

  groups = {
    oidc_users = {
      name = "OIDC Users"

      include = {
        idp_keys = ["oidc"]
      }
    }
  }

  applications = {
    app = {
      name             = var.application_name
      domain           = var.application_domain
      group_keys       = ["oidc_users"]
      allowed_idp_keys = ["oidc"]
    }
  }
}
