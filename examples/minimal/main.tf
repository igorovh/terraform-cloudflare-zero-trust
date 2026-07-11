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

  groups = {
    admins = {
      name = "Admins"

      include = {
        emails = var.admin_emails
      }
    }
  }

  applications = {
    app = {
      name       = var.application_name
      domain     = var.application_domain
      group_keys = ["admins"]
    }
  }
}
