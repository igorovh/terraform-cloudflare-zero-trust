# Identity Broker Example

Creates the Worker in `../../identity-broker` and registers it as a Generic OIDC identity provider for Cloudflare Access.

```bash
terraform init
terraform plan
```

The value of `identity_broker_client_secret` is used both by Cloudflare Access and as the Worker's `OIDC_CLIENT_SECRET` binding.

The example serves a minimal status page on `identity.enhancer.at`. Set `home_redirect_url` in `main.tf` if you want `/` to redirect elsewhere.

To use `test-identity.enhancer.at`, change `identity_broker_hostname` in `main.tf` and update GitHub/Discord OAuth callback URLs.

Generate `identity_broker_jwt_private_jwk` with:

```bash
cd ../../identity-broker
npm install
npm run generate-key
```
