# Local Test

This directory uses the module from `../` so you can test local edits before publishing a tag.

It is wired for the Identity Broker OIDC flow.

```bash
cp secrets.tfvars.example secrets.tfvars
terraform init
terraform plan -var-file="secrets.tfvars"
```

Edit non-secret local values directly in `main.tf`: `cloudflare_account_id`, `identity_broker_hostname`, principal IDs, aliases, and `domain`.

Set `identity_broker_hostname = "test-identity.enhancer.at"` if you want a separate test broker. Update GitHub/Discord OAuth callback URLs to match the selected hostname.

Set `home_redirect_url` in the `identity_broker` block if the root page should redirect somewhere else.

Put only secrets in `secrets.tfvars`: `cloudflare_api_token` and `identity_broker_client_secret`. Do not commit real `secrets.tfvars` or Terraform state files.
