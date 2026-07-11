output "identity_provider_ids" {
  value       = local.identity_provider_ids
  description = "Map of identity provider key to Cloudflare Access identity provider ID."
}

output "identity_broker_worker_script_name" {
  value       = try(cloudflare_workers_script.identity_broker[0].script_name, null)
  description = "Terraform-managed Identity Broker Worker script name."
}

output "identity_broker_worker_custom_domain" {
  value       = try(cloudflare_workers_custom_domain.identity_broker[0].hostname, null)
  description = "Terraform-managed Identity Broker Worker custom domain hostname."
}

output "identity_provider_redirect_urls" {
  value = {
    for key, provider in cloudflare_zero_trust_access_identity_provider.this :
    key => provider.config.redirect_url
  }
  description = "Map of created identity provider key to Cloudflare Access redirect URL."
}

output "group_ids" {
  value       = { for key, group in cloudflare_zero_trust_access_group.this : key => group.id }
  description = "Map of group key to Cloudflare Access group ID."
}

output "application_ids" {
  value       = { for key, app in cloudflare_zero_trust_access_application.this : key => app.id }
  description = "Map of application key to Cloudflare Access application ID."
}

output "application_auds" {
  value       = { for key, app in cloudflare_zero_trust_access_application.this : key => app.aud }
  description = "Map of application key to Cloudflare Access AUD tag."
}
