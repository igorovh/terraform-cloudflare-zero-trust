variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account ID used for Zero Trust resources."
}

variable "identity_providers" {
  type = map(object({
    name = string
    type = string

    config = optional(object({
      apps_domain             = optional(string)
      attributes              = optional(list(string))
      auth_url                = optional(string)
      authorization_server_id = optional(string)
      certs_url               = optional(string)
      claims                  = optional(list(string))
      client_id               = optional(string)
      client_secret           = optional(string)
      directory_id            = optional(string)
      email_attribute_name    = optional(string)
      email_claim_name        = optional(string)
      issuer_url              = optional(string)
      okta_account            = optional(string)
      pkce_enabled            = optional(bool)
      scopes                  = optional(list(string))
      sign_request            = optional(bool)
      sso_target_url          = optional(string)
      support_groups          = optional(bool)
      token_url               = optional(string)
    }), {})
  }))
  description = "Identity providers to create. Provider-specific settings, including client_secret, go in config."
  default     = {}
}

variable "existing_identity_provider_ids" {
  type        = map(string)
  description = "Existing Cloudflare Access identity provider IDs keyed by local name."
  default     = {}
}

variable "identity_broker" {
  type = object({
    enabled                      = optional(bool, true)
    script_name                  = optional(string, "cloudflare-zero-trust-identity-broker")
    compatibility_date           = optional(string, "2026-06-27")
    issuer                       = string
    cloudflare_team_name         = string
    brand_name                   = optional(string, "Enhancer Identity")
    home_redirect_url            = optional(string)
    oidc_client_id               = optional(string, "cloudflare-access")
    oidc_client_secret           = string
    jwt_private_jwk              = string
    durable_object_migration_tag = optional(string, "v1")
    discord_role_guild_ids       = optional(list(string), [])

    github = optional(object({
      client_id     = string
      client_secret = string
    }), null)

    discord = optional(object({
      client_id     = string
      client_secret = string
    }), null)

    custom_domain = optional(object({
      hostname  = string
      zone_id   = optional(string)
      zone_name = optional(string)
    }), null)
  })
  description = "Optional Terraform-managed Identity Broker Worker configuration. Secrets are stored in Terraform state."
  default     = null

  validation {
    condition     = var.identity_broker == null || startswith(var.identity_broker.issuer, "https://")
    error_message = "identity_broker.issuer must use https://."
  }

  validation {
    condition     = var.identity_broker == null || can(regex("^[a-z0-9-]+$", var.identity_broker.cloudflare_team_name))
    error_message = "identity_broker.cloudflare_team_name must be a Cloudflare Access team subdomain, for example my-team from https://my-team.cloudflareaccess.com."
  }

  validation {
    condition     = var.identity_broker == null || var.identity_broker.home_redirect_url == null || startswith(var.identity_broker.home_redirect_url, "https://")
    error_message = "identity_broker.home_redirect_url must use https:// when set."
  }
}

variable "groups" {
  type = map(object({
    name       = string
    user_keys  = optional(list(string), [])
    principals = optional(list(string), [])

    include = optional(object({
      emails        = optional(list(string), [])
      email_domains = optional(list(string), [])
      everyone      = optional(bool, false)
      idp_keys      = optional(list(string), [])
    }), {})

    require = optional(object({
      github = optional(object({
        idp_key = string
        org     = string
        teams   = optional(list(string), [])
      }), null)
    }), {})

    github = optional(object({
      idp_key = string
      org     = string
      teams   = optional(list(string), [])
    }), null)
  }))
  description = "Access groups. The old members format is intentionally not supported."
  default     = {}

  validation {
    condition = alltrue([
      for _, group in var.groups : !group.include.everyone || (
        length(group.user_keys) == 0
        && length(group.principals) == 0
        && length(group.include.emails) == 0
        && length(group.include.email_domains) == 0
        && length(group.include.idp_keys) == 0
        && group.github == null
      )
    ])
    error_message = "groups[*].include.everyone cannot be combined with other include selectors."
  }
}

variable "users" {
  type = map(object({
    principals = optional(list(string), [])

    oidc_claims = optional(list(object({
      idp_key     = string
      claim_name  = string
      claim_value = string
    })), [])
  }))
  description = "Local user/principal declarations that groups can reference by user_keys. These do not create Cloudflare users. Use email:<address> inside principals for email identities."
  default     = {}

  validation {
    condition = alltrue(flatten([
      for _, user in var.users : [
        for principal in user.principals : !startswith(principal, "email:") || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", trimprefix(principal, "email:")))
      ]
    ]))
    error_message = "Email principals must use email:<address>, for example email:igor@enhancer.at."
  }
}

variable "principal_aliases" {
  type        = map(string)
  description = "Friendly principal aliases mapped to canonical principal strings, for example discord:role:enhancer/dev -> discord:role:<guild_id>/<role_id>."
  default     = {}
}

variable "principal_idp_key" {
  type        = string
  description = "Identity provider key whose OIDC claim contains principal strings. Required for non-email principals."
  default     = null
}

variable "principal_claim_name" {
  type        = string
  description = "OIDC claim name containing principal strings emitted by the identity broker."
  default     = "zt_principals"
}

variable "applications" {
  type = map(object({
    name                      = string
    domain                    = string
    type                      = optional(string, "self_hosted")
    session_duration          = optional(string, "24h")
    group_keys                = optional(list(string), [])
    allowed_idp_keys          = optional(list(string), [])
    auto_redirect_to_identity = optional(bool, false)
    app_launcher_visible      = optional(bool, true)
  }))
  description = "Applications to protect with Cloudflare Zero Trust Access."
  default     = {}

  validation {
    condition = alltrue([
      for _, app in var.applications : length(app.group_keys) > 0
    ])
    error_message = "Each application must reference at least one group_key."
  }

  validation {
    condition = alltrue([
      for _, app in var.applications : !app.auto_redirect_to_identity || length(app.allowed_idp_keys) == 1
    ])
    error_message = "auto_redirect_to_identity requires exactly one allowed_idp_key."
  }
}
