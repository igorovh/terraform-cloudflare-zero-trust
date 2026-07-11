variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_account_id" {
  type = string
}

variable "github_client_id" {
  type = string
}

variable "github_client_secret" {
  type      = string
  sensitive = true
}

variable "github_org" {
  type = string
}

variable "github_teams" {
  type    = list(string)
  default = []
}

variable "application_name" {
  type    = string
  default = "Example App"
}

variable "application_domain" {
  type = string
}
