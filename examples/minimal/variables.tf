variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_account_id" {
  type = string
}

variable "admin_emails" {
  type = list(string)
}

variable "application_name" {
  type    = string
  default = "Example App"
}

variable "application_domain" {
  type = string
}
