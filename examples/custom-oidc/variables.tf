variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_account_id" {
  type = string
}

variable "oidc_name" {
  type    = string
  default = "Custom OIDC"
}

variable "oidc_client_id" {
  type = string
}

variable "oidc_client_secret" {
  type      = string
  sensitive = true
}

variable "oidc_auth_url" {
  type = string
}

variable "oidc_token_url" {
  type = string
}

variable "oidc_certs_url" {
  type = string
}

variable "application_name" {
  type    = string
  default = "Example App"
}

variable "application_domain" {
  type = string
}
