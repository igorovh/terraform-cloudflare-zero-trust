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
    github_admins = {
      name = "GitHub Admins"

      github = {
        idp_key = "github"
        org     = var.github_org
        teams   = var.github_teams
      }
    }
  }

  applications = {
    app = {
      name             = var.application_name
      domain           = var.application_domain
      group_keys       = ["github_admins"]
      allowed_idp_keys = ["github"]
    }
  }
}
