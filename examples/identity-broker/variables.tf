variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_account_id" {
  type = string
}

variable "cloudflare_team_name" {
  type        = string
  description = "Cloudflare Zero Trust team subdomain, for example my-team from https://my-team.cloudflareaccess.com."
}

variable "identity_broker_client_secret" {
  type      = string
  sensitive = true
}

variable "identity_broker_jwt_private_jwk" {
  type      = string
  sensitive = true
}

variable "github_client_secret" {
  type      = string
  sensitive = true
}

variable "discord_client_secret" {
  type      = string
  sensitive = true
}
